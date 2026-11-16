import dataclasses
import datetime
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
    ttl: datetime.timedelta | None = None
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


class Lookup:
    """Resolve the DNS records one check needs through a cached resolver."""

    DNS_TIMEOUT = datetime.timedelta(seconds=2)
    DNS_RETRIES = 3
    DNS_RETRY_DELAY = datetime.timedelta(seconds=0.2)
    AUTHORITATIVE_TIMEOUT = datetime.timedelta(seconds=2)
    AUTHORITATIVE_TRIES = 2
    TRANSIENT_ERRORS = (
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
    )

    def __init__(self) -> None:
        self._memo: dict[tuple[dns.rdatatype.RdataType, str], Answer] = {}
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

    def query(self, name: str, record_type: dns.rdatatype.RdataType) -> Answer:
        """Resolve one name and type, retrying transient resolver failures."""
        key = record_type, name.lower().rstrip(".")
        if (answer := self._memo.get(key)) is not None:
            return answer
        for attempt in range(self.DNS_RETRIES):
            try:
                answers = self._resolver.resolve(name, record_type)
            except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
                answer = Answer()
                break
            except self.TRANSIENT_ERRORS:
                if attempt == self.DNS_RETRIES - 1:
                    answer = Answer(failed=True)
                    break
                time.sleep((self.DNS_RETRY_DELAY * 2**attempt).total_seconds())
            except dns.exception.DNSException:
                answer = Answer(failed=True)
                break
            else:
                answer = Answer(
                    tuple(
                        self.render_record(record, record_type) for record in answers
                    ),
                    ttl=datetime.timedelta(seconds=answers.rrset.ttl),
                    canonical_name=str(answers.canonical_name).rstrip("."),
                )
                break
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
    ) -> datetime.timedelta | None:
        answer = self.query(name, record_type)
        if answer.failed or not answer.records:
            return None
        published = self.authoritative_ttl(answer.canonical_name or name, record_type)
        if published is None or published == answer.ttl:
            return answer.ttl
        self._memo[record_type, name.lower().rstrip(".")] = dataclasses.replace(
            answer, ttl=published
        )
        return published

    def authoritative_nameservers(self, name: str):
        candidate = dns.name.from_text(name)
        while len(candidate) > 1:
            try:
                answer = self._resolver.resolve(
                    candidate, dns.rdatatype.NS, raise_on_no_answer=False
                )
            except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
                answer = None
            except dns.exception.DNSException:
                return None
            if answer is not None and len(answer):
                return answer
            candidate = candidate.parent()
        return None

    def authoritative_ttl(
        self, name: str, record_type: dns.rdatatype.RdataType
    ) -> datetime.timedelta | None:
        """Read the TTL the zone publishes, not the decayed one from a cache."""
        if nameservers := self.authoritative_nameservers(name):
            for nameserver in list(nameservers)[: self.AUTHORITATIVE_TRIES]:
                try:
                    addresses = self._resolver.resolve(
                        nameserver.target, dns.rdatatype.A
                    )
                    authority = dns.resolver.Resolver(configure=False)
                    authority.lifetime = self.AUTHORITATIVE_TIMEOUT.total_seconds()
                    authority.nameservers = [addresses[0].address]
                    answer = authority.resolve(name, record_type)
                except dns.exception.DNSException:
                    ttl = None
                else:
                    ttl = datetime.timedelta(seconds=answer.rrset.ttl)
                if ttl is not None:
                    return ttl
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
