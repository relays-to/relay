import base64
import gzip
import io
import logging
import lzma
import re
import zipfile
import zlib
from compression import zstd
from email import message_from_bytes
from email.errors import HeaderParseError
from email.header import Header, decode_header
from pathlib import PurePath

logger = logging.getLogger(__name__)


class MissingAttachmentError(ValueError):
    """The email contains no attachment."""


class SkippedPartError(ValueError):
    """The MIME part is not a report attachment."""


class ReportAttachmentError(ValueError):
    """The report attachment cannot produce a payload."""


def decode_header_value(value: str | Header) -> str:
    """
    Return an RFC 2047-decoded header value as unfolded text.

    Undecodable bytes become U+FFFD. Malformed encoded-words and
    values mixing encoded-words with raw 8-bit bytes keep their raw
    form.
    """
    if not value:
        return ""
    text = value
    if not isinstance(value, Header):
        # Unfold before decoding so folded whitespace survives.
        text = re.sub(r"\r\n|\r|\n", "", value)
    # str() would replace 8-bit bytes with U+FFFD before they decode.
    try:
        chunks = decode_header(text)
    except HeaderParseError:
        # Malformed encoded-word; keep the raw value.
        chunks = [(str(text), None)]
    parts = []
    for data, charset in chunks:
        if isinstance(data, str):
            parts.append(data)
            continue
        if charset in (None, "unknown-8bit"):
            charset = "utf-8"
        try:
            parts.append(data.decode(charset, "replace"))
        except LookupError:
            parts.append(data.decode("utf-8", "replace"))
    text = "".join(parts)
    if not text and value:
        # Undecodable payload decodes to nothing; keep the raw value.
        text = str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # Repair surrogate escapes from raw 8-bit input.
        text = text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return re.sub(r"\r\n|\r|\n", "", text)


def decode_payload(payload: bytes, charset: str | None) -> str:
    """
    Decode a MIME payload with its declared charset, falling back to UTF-8.

    Incoming mail chooses the charset label, and an unknown one raises
    `LookupError` rather than a `UnicodeError`.
    """
    try:
        return payload.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract_part_text(part):
    """Extract text content from a MIME part, including sub-messages and base64 data."""
    if part.is_multipart():
        for sub in part.get_payload():
            if payload := sub.get_payload(decode=True):
                # Python's email parser may return base64 bytes when CTE is set
                # but the sub-message structure doesn't honor it
                try:
                    stripped = bytes(payload).strip()
                    decoded = base64.b64decode(stripped)
                    re_encoded = base64.b64encode(decoded)
                    if re_encoded == stripped.replace(b"\n", b"").replace(b"\r", b""):
                        payload = decoded
                except ValueError, TypeError:
                    pass  # payload is not base64-encoded, use as-is
                return payload.decode("utf-8", errors="replace")
        return ""
    if payload := part.get_payload(decode=True):
        return payload.decode("utf-8", errors="replace")
    return ""


class ReportAttachment:
    """An attachment carried by a raw report email."""

    MAX_BYTES = 10 * 1024 * 1024

    DECOMPRESSION_ERRORS = (
        OSError,
        EOFError,
        zlib.error,
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
        lzma.LZMAError,
        zstd.ZstdError,
    )

    CONTENT_TYPE_SUFFIXES = {
        "application/gzip": ".gz",
        "application/x-gzip": ".gz",
        "application/zip": ".zip",
        "application/x-zip-compressed": ".zip",
    }
    SUFFIXES = (".gz", ".zip", ".xml", ".json")
    CONTENT_TYPES = {
        *CONTENT_TYPE_SUFFIXES,
        "application/xml",
        "text/xml",
        "application/json",
    }

    @classmethod
    def iterate_from(cls, raw_bytes):
        """Yield decompressed attachment payloads from a raw email."""
        message = message_from_bytes(raw_bytes)
        for part in message.walk():
            try:
                payload = cls.from_part(part)
            except SkippedPartError:
                pass
            except ReportAttachmentError as error:
                logger.warning("Skipped attachment %r: %s", part.get_filename(), error)
            else:
                yield payload

    @classmethod
    def from_part(cls, part):
        """Return the decompressed payload of one report attachment."""
        filename = part.get_filename() or ""
        lower_filename = filename.lower()
        content_type = part.get_content_type()
        is_report_attachment = bool(lower_filename) and (
            lower_filename.endswith(cls.SUFFIXES) or content_type in cls.CONTENT_TYPES
        )
        is_attachment = part.get_content_disposition() == "attachment"
        if (is_attachment or is_report_attachment) and (
            payload := part.get_payload(decode=True)
        ):
            suffix = PurePath(lower_filename).suffix
            if suffix not in (".gz", ".zip"):
                suffix = cls.CONTENT_TYPE_SUFFIXES.get(content_type, suffix)
            try:
                match suffix:
                    case ".gz":
                        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
                            payload = stream.read(cls.MAX_BYTES + 1)
                    case ".zip":
                        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                            if entry := next(
                                (
                                    info
                                    for info in archive.infolist()
                                    if not info.is_dir()
                                ),
                                None,
                            ):
                                with archive.open(entry) as stream:
                                    payload = stream.read(cls.MAX_BYTES + 1)
                            else:
                                raise ReportAttachmentError("no file entry")  # noqa: TRY003
            except cls.DECOMPRESSION_ERRORS as error:
                raise ReportAttachmentError("failed to decompress") from error  # noqa: TRY003
            if len(payload) > cls.MAX_BYTES:
                raise ReportAttachmentError("larger than the size limit")  # noqa: TRY003
            return payload
        raise SkippedPartError
