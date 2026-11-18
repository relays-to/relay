import dataclasses
import datetime as dt
import ipaddress
import time

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver


@dataclasses.dataclass(frozen=True, slots=True)
class Answer:
    records: tuple[str, ...] = ()
    failed: bool = False
    ttl: dt.timedelta | None = None
    canonical_name: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class MxRecord:
    preference: int
    exchange: str


@dataclasses.dataclass(frozen=True, slots=True)
class MxLookup:
    records: tuple[MxRecord, ...] = ()
    failed: bool = False

    @property
    def exchanges(self) -> tuple[str, ...]:
        return tuple(record.exchange for record in self.records if record.exchange)

    @property
    def null(self) -> bool:
        return any(
            record.preference == 0 and not record.exchange for record in self.records
        )


@dataclasses.dataclass(frozen=True, slots=True)
class AsnRecord:
    asn: str
    country_code: str
    network_name: str = ""


class Lookup:
    """Resolve the DNS records one check needs through a cached resolver."""

    DNS_TIMEOUT = dt.timedelta(seconds=2)
    DNS_RETRIES = 3
    DNS_RETRY_DELAY = dt.timedelta(seconds=0.2)
    AUTHORITATIVE_TIMEOUT = dt.timedelta(seconds=3)
    AUTHORITATIVE_TRY_TIMEOUT = dt.timedelta(seconds=1)
    AUTHORITATIVE_TRIES = 2
    ASN_TIMEOUT = dt.timedelta(seconds=1)
    TRANSIENT_ERRORS = (
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
    )

    def __init__(self) -> None:
        self._memo: dict[tuple[dns.rdatatype.RdataType, str], Answer] = {}
        self._asn_memo: dict[str, AsnRecord | None] = {}
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = self.DNS_TIMEOUT.total_seconds()
        self._resolver.cache = dns.resolver.Cache()

    @staticmethod
    def render_record(record, record_type: dns.rdatatype.RdataType) -> str:
        """Render one record as the text the checks compare."""
        match record_type:
            case dns.rdatatype.TXT:
                return b"".join(record.strings).decode("utf-8", "replace")
            case dns.rdatatype.MX:
                return f"{record.preference} {str(record.exchange).rstrip('.')}"
            case dns.rdatatype.A | dns.rdatatype.AAAA:
                return record.address
            case _:
                return str(record)

    def resolve(
        self,
        resolver: dns.resolver.Resolver,
        name: str,
        record_type: dns.rdatatype.RdataType,
        tries: int,
        lifetime: dt.timedelta | None = None,
    ) -> dns.resolver.Answer:
        deadline = (
            None if lifetime is None else time.monotonic() + lifetime.total_seconds()
        )
        for attempt in range(tries):
            remaining = (
                resolver.lifetime if deadline is None else deadline - time.monotonic()
            )
            if remaining <= 0:
                raise dns.exception.Timeout()
            try:
                return resolver.resolve(name, record_type, lifetime=remaining)
            except self.TRANSIENT_ERRORS:
                if attempt == tries - 1:
                    raise
                time.sleep((self.DNS_RETRY_DELAY * 2**attempt).total_seconds())
        raise dns.exception.Timeout()

    def query(
        self,
        name: str,
        record_type: dns.rdatatype.RdataType,
        lifetime: dt.timedelta | None = None,
    ) -> Answer:
        """Resolve one name and type, retrying transient resolver failures."""
        key = record_type, name.lower().rstrip(".")
        if (answer := self._memo.get(key)) is not None:
            return answer
        try:
            answers = self.resolve(
                self._resolver, name, record_type, self.DNS_RETRIES, lifetime
            )
        except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
            answer = Answer()
        except dns.exception.DNSException:
            answer = Answer(failed=True)
        else:
            answer = Answer(
                tuple(self.render_record(record, record_type) for record in answers),
                ttl=dt.timedelta(seconds=answers.rrset.ttl),
                canonical_name=str(answers.canonical_name).rstrip("."),
            )
        if not answer.failed or lifetime is None:
            self._memo[key] = answer
        return answer

    def text(self, name: str) -> tuple[str, ...] | None:
        answer = self.query(name, dns.rdatatype.TXT)
        return None if answer.failed else answer.records

    def addresses(self, host: str) -> tuple[str, ...]:
        return (
            self.query(host, dns.rdatatype.A).records
            + self.query(host, dns.rdatatype.AAAA).records
        )

    def ttl(
        self, name: str, record_type: dns.rdatatype.RdataType
    ) -> dt.timedelta | None:
        answer = self.query(name, record_type)
        if answer.failed or not answer.records:
            return None
        published = self.authoritative_ttl(answer.canonical_name or name, record_type)
        if published is None:
            return None
        self._memo[record_type, name.lower().rstrip(".")] = dataclasses.replace(
            answer, ttl=published
        )
        return published

    def authoritative_nameservers(self, name: str):
        candidate = dns.name.from_text(name)
        deadline = time.monotonic() + self.AUTHORITATIVE_TIMEOUT.total_seconds()
        while len(candidate) > 1 and (remaining := deadline - time.monotonic()) > 0:
            try:
                answer = self.resolve(
                    self._resolver,
                    str(candidate),
                    dns.rdatatype.NS,
                    self.DNS_RETRIES,
                    dt.timedelta(seconds=remaining / (len(candidate) - 1)),
                )
            except dns.exception.DNSException:
                pass
            else:
                return answer
            candidate = candidate.parent()
        return None

    def authoritative_ttl(
        self, name: str, record_type: dns.rdatatype.RdataType
    ) -> dt.timedelta | None:
        """Read the TTL the zone publishes, not the decayed one from a cache."""
        if nameservers := self.authoritative_nameservers(name):
            deadline = time.monotonic() + self.AUTHORITATIVE_TIMEOUT.total_seconds()
            addresses = (
                address
                for nameserver in list(nameservers)[: self.AUTHORITATIVE_TRIES]
                if (remaining := deadline - time.monotonic()) > 0
                for address in self.query(
                    str(nameserver.target),
                    dns.rdatatype.A,
                    dt.timedelta(seconds=remaining),
                ).records
                if (ip := ipaddress.ip_address(address)).is_global
                and not ip.is_multicast
            )
            authority = dns.resolver.Resolver(configure=False)
            authority.timeout = self.AUTHORITATIVE_TRY_TIMEOUT.total_seconds()
            for address in addresses:
                if (remaining := deadline - time.monotonic()) <= 0:
                    break
                authority.nameservers = [address]
                try:
                    answer = self.resolve(
                        authority,
                        name,
                        record_type,
                        self.AUTHORITATIVE_TRIES,
                        dt.timedelta(seconds=remaining),
                    )
                except dns.exception.DNSException:
                    pass
                else:
                    return dt.timedelta(seconds=answer.rrset.ttl)
        return None

    def ptr(self, address: str) -> tuple[str, ...] | None:
        answer = self.query(
            ipaddress.ip_address(address).reverse_pointer, dns.rdatatype.PTR
        )
        if answer.failed:
            return None
        return tuple(name.rstrip(".") for name in answer.records)

    def mx(self, name: str) -> MxLookup:
        answer = self.query(name, dns.rdatatype.MX)
        if answer.failed:
            return MxLookup(failed=True)
        records = (
            MxRecord(int(preference), exchange)
            for preference, _, exchange in (
                record.partition(" ") for record in answer.records
            )
        )
        return MxLookup(
            records=tuple(sorted(records, key=lambda record: record.preference))
        )

    def fetch_txt_fields(self, query: str) -> list[str] | None:
        try:
            answer = self.resolve(
                self._resolver,
                query,
                dns.rdatatype.TXT,
                1,
                self.ASN_TIMEOUT,
            )
        except dns.exception.DNSException:
            answer = ()
        fields = None
        for record in answer:
            candidate = [
                field.strip()
                for field in self.render_record(record, dns.rdatatype.TXT).split("|")
            ]
            if len(candidate) >= 2:
                fields = candidate
                break
        return fields

    def fetch_asn(self, address: str) -> AsnRecord | None:
        record = self._asn_memo.get(address)
        if address not in self._asn_memo:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                ip = None
            if ip is not None:
                if isinstance(ip, ipaddress.IPv6Address):
                    nibbles = ip.exploded.replace(":", "")
                    query = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
                else:
                    query = (
                        ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
                    )
                if (origin := self.fetch_txt_fields(query)) and (
                    asns := origin[0].split()
                ):
                    asn = asns[0]
                    prefix_country = origin[2] if len(origin) > 2 else ""
                    asn_fields = self.fetch_txt_fields(f"AS{asn}.asn.cymru.com")
                    country_code = (
                        asn_fields[1] if asn_fields and len(asn_fields) > 1 else ""
                    ).upper() or prefix_country.upper()
                    network_name = (
                        asn_fields[4].split(" - ", 1)[-1].rsplit(",", 1)[0].strip()
                        if asn_fields and len(asn_fields) > 4
                        else ""
                    )
                    record = AsnRecord(
                        asn=asn,
                        country_code=country_code,
                        network_name=network_name,
                    )
            self._asn_memo[address] = record
        return record
