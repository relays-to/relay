import dataclasses
import ipaddress
import time

import dns.exception
import dns.rdatatype
import dns.resolver


@dataclasses.dataclass(frozen=True, slots=True)
class Answer:
    records: tuple[str, ...] = ()
    failed: bool = False
    ttl_secs: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class MxLookup:
    exchanges: tuple[str, ...] = ()
    null: bool = False
    failed: bool = False


class Lookup:
    """Resolve the DNS records one check needs through a cached resolver."""

    DNS_TIMEOUT_SECS = 2.0
    DNS_RETRIES = 3
    DNS_RETRY_DELAY_SECS = 0.2
    AUTHORITATIVE_TIMEOUT_SECS = 2.0
    AUTHORITATIVE_TRIES = 2
    TRANSIENT_ERRORS = (
        dns.exception.Timeout,
        dns.resolver.LifetimeTimeout,
        dns.resolver.NoNameservers,
    )

    def __init__(self) -> None:
        self._memo: dict[tuple[dns.rdatatype.RdataType, str], Answer] = {}
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = self.DNS_TIMEOUT_SECS
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
                time.sleep(self.DNS_RETRY_DELAY_SECS * 2**attempt)
            except dns.exception.DNSException:
                answer = Answer(failed=True)
                break
            else:
                answer = Answer(
                    tuple(
                        self.render_record(record, record_type) for record in answers
                    ),
                    ttl_secs=(answers.rrset.ttl if answers.rrset is not None else None),
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

    def ttl_secs(self, name: str, record_type: dns.rdatatype.RdataType) -> int | None:
        answer = self.query(name, record_type)
        if answer.failed or not answer.records:
            return None
        published_secs = self.authoritative_ttl_secs(name, record_type)
        if published_secs is None or published_secs == answer.ttl_secs:
            return answer.ttl_secs
        self._memo[record_type, name.lower().rstrip(".")] = dataclasses.replace(
            answer, ttl_secs=published_secs
        )
        return published_secs

    def authoritative_ttl_secs(
        self, name: str, record_type: dns.rdatatype.RdataType
    ) -> int | None:
        """Read the TTL the zone publishes, not the decayed one from a cache."""
        try:
            zone = dns.resolver.zone_for_name(name, resolver=self._resolver)
            nameservers = self._resolver.resolve(zone, dns.rdatatype.NS)
        except dns.exception.DNSException:
            return None
        for nameserver in list(nameservers)[: self.AUTHORITATIVE_TRIES]:
            try:
                addresses = self._resolver.resolve(nameserver.target, dns.rdatatype.A)
                authority = dns.resolver.Resolver(configure=False)
                authority.lifetime = self.AUTHORITATIVE_TIMEOUT_SECS
                authority.nameservers = [addresses[0].address]
                answer = authority.resolve(name, record_type)
            except dns.exception.DNSException:
                ttl_secs = None
            else:
                ttl_secs = answer.rrset.ttl if answer.rrset is not None else None
            if ttl_secs is not None:
                return ttl_secs
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
        records = [record.split(" ", 1) for record in answer.records]
        return MxLookup(
            exchanges=tuple(exchange for _, exchange in records if exchange),
            null=any(
                preference == "0" and not exchange for preference, exchange in records
            ),
        )
