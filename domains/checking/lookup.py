import dataclasses
import hashlib
import ipaddress
import time

import dns.exception
import dns.resolver
from django.core.cache import cache

DNS_TIMEOUT_SECS = 2.0
DNS_RETRIES = 3
DNS_RETRY_DELAY_SECS = 0.2
DNS_CACHE_SECS = 300

TRANSIENT_ERRORS = (
    dns.exception.Timeout,
    dns.resolver.LifetimeTimeout,
    dns.resolver.NoNameservers,
)


@dataclasses.dataclass(frozen=True, slots=True)
class Answer:
    records: tuple[str, ...] = ()
    failed: bool = False
    ttl: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class MxLookup:
    exchanges: tuple[str, ...] = ()
    null: bool = False
    failed: bool = False


def render_record(record, record_type: str) -> str:
    match record_type:
        case "TXT":
            return b"".join(record.strings).decode("utf-8", "replace")
        case "MX":
            return f"{record.preference} {str(record.exchange).rstrip('.')}"
        case "A" | "AAAA":
            return record.address
        case _:
            return str(record)


class Lookup:
    def __init__(self) -> None:
        self._memo: dict[tuple[str, str], Answer] = {}

    def query(self, name: str, record_type: str) -> Answer:
        key = record_type, name.lower().rstrip(".")
        if key in self._memo:
            return self._memo[key]
        digest = hashlib.sha256(key[1].encode()).hexdigest()
        cache_key = f"domain_check:lookup:{record_type}:{digest}"
        if (cached := cache.get(cache_key)) is not None:
            answer = Answer(
                tuple(cached["records"]), cached["failed"], cached.get("ttl")
            )
        else:
            for attempt in range(DNS_RETRIES):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.lifetime = DNS_TIMEOUT_SECS
                    answers = resolver.resolve(name, record_type)
                except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
                    answer = Answer()
                    break
                except TRANSIENT_ERRORS:
                    if attempt == DNS_RETRIES - 1:
                        answer = Answer(failed=True)
                        break
                    time.sleep(DNS_RETRY_DELAY_SECS * 2**attempt)
                except dns.exception.DNSException:
                    answer = Answer(failed=True)
                    break
                else:
                    answer = Answer(
                        tuple(render_record(record, record_type) for record in answers),
                        ttl=answers.rrset.ttl if answers.rrset is not None else None,
                    )
                    break
            if not answer.failed:
                cache.set(cache_key, dataclasses.asdict(answer), DNS_CACHE_SECS)
        self._memo[key] = answer
        return answer

    def text(self, name: str) -> tuple[str, ...] | None:
        answer = self.query(name, "TXT")
        return None if answer.failed else answer.records

    def addresses(self, host: str) -> tuple[str, ...]:
        return self.query(host, "A").records + self.query(host, "AAAA").records

    def ttl(self, name: str, record_type: str) -> int | None:
        return self.query(name, record_type).ttl

    def ptr(self, address: str) -> tuple[str, ...] | None:
        answer = self.query(ipaddress.ip_address(address).reverse_pointer, "PTR")
        if answer.failed:
            return None
        return tuple(name.rstrip(".") for name in answer.records)

    def mx(self, name: str) -> MxLookup:
        answer = self.query(name, "MX")
        if answer.failed:
            return MxLookup(failed=True)
        records = [record.split(" ", 1) for record in answer.records]
        return MxLookup(
            exchanges=tuple(exchange for _, exchange in records if exchange),
            null=any(
                preference == "0" and not exchange for preference, exchange in records
            ),
        )
