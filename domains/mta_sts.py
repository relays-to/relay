"""Pure MTA-STS record helpers shared by verification and the public check."""

import re


class MtaStsRecord:
    """Validate the tags of an MTA-STS TXT record and match its MX patterns."""

    EXTENSION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
    EXTENSION_VALUE = re.compile(r"[\x21-\x3A\x3C\x3E-\x7E]+")
    ID = re.compile(r"[A-Za-z0-9]{1,32}")

    @classmethod
    def parse(cls, value: str) -> dict[str, str] | None:
        """Return valid MTA-STS tags, or `None` for a malformed record."""
        fields = value.split(";")
        if fields[0] != "v=STSv1":
            return None
        if fields[-1].strip(" \t") == "":
            fields.pop()

        tags: dict[str, str] = {}
        for field in fields[1:]:
            field = field.strip(" \t")
            if "=" not in field:
                return None
            name, tag_value = field.split("=", 1)
            if name in tags:
                return None
            if name == "id":
                if cls.ID.fullmatch(tag_value) is None:
                    return None
            elif (
                cls.EXTENSION_NAME.fullmatch(name) is None
                or cls.EXTENSION_VALUE.fullmatch(tag_value) is None
            ):
                return None
            tags[name] = tag_value
        return tags if "id" in tags else None

    @staticmethod
    def matches(hostname: str, pattern: str) -> bool:
        """Return whether an MX hostname matches an MTA-STS mx pattern."""
        hostname = hostname.rstrip(".").lower()
        pattern = pattern.rstrip(".").lower()
        if pattern.startswith("*."):
            label, _, suffix = hostname.partition(".")
            return bool(label) and suffix == pattern.removeprefix("*.")
        return hostname == pattern
