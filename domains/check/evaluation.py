import concurrent.futures
import dataclasses
import functools
import hashlib
import ipaddress
import time
from collections.abc import Iterable, Iterator, Mapping
from urllib.parse import urlsplit, urlunsplit

import dns.rdatatype
import httpx
from django.conf import settings
from django.core.cache import cache

from abstract.blocklists import (
    PUBLIC_ADDRESS_PROVIDERS,
    REFUSAL_NETWORK,
    BlocklistProvider,
    reverse_pointer,
)
from domains.mailauth import DmarcPolicy
from domains.mta_sts import MtaStsRecord

from .lookup import Lookup


@dataclasses.dataclass(frozen=True, slots=True)
class SubCheck:
    label: str
    status: str
    detail: str
    severity: str = "broken"
    addresses: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class CheckResult:
    key: str
    label: str
    detail: str
    subchecks: tuple[SubCheck, ...] = ()

    @property
    def status(self) -> str:
        if any(
            subcheck.status == "fail" and subcheck.severity != "weak"
            for subcheck in self.subchecks
        ):
            return "fail"
        if any(subcheck.status == "fail" for subcheck in self.subchecks):
            return "partial"
        if any(subcheck.status == "pass" for subcheck in self.subchecks):
            return "pass"
        return "partial"


class Check:
    """
    Grade one aspect of a domain's mail configuration.

    A subclass owns the constants and the hints for its own subchecks. Anything
    that more than one check needs lives here and is inherited.
    """

    key: str
    label: str
    slug: str | None = None
    hints: Mapping[str, str] = {}
    TTL_MIN_SECS = 3600
    # Resolvers return the remaining TTL, so an hour-long record can answer with
    # minutes left. Absorb that countdown before calling a record too short-lived.
    TTL_TOLERANCE_SECS = 300
    TTL_HINT = "Raise the record's TTL to at least 3600 seconds."
    MAX_LISTED_ADDRESSES = 5
    TRANSITION_NETWORKS = (
        ipaddress.ip_network("64:ff9b::/96"),
        ipaddress.ip_network("64:ff9b:1::/48"),
        ipaddress.ip_network("2002::/16"),
        ipaddress.ip_network("2001::/32"),
    )

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        """Grade the domain and return the result of this check."""
        raise NotImplementedError

    @classmethod
    def hint(cls, label: str) -> str:
        """Return the remediation hint for a subcheck label."""
        if label.endswith("TTL"):
            return cls.TTL_HINT
        return cls.hints.get(label, "")

    @classmethod
    def result(
        cls, subchecks: Iterable[SubCheck], detail: str | None = None
    ) -> CheckResult:
        """Collect the subchecks into a result that summarizes them by default."""
        subchecks = tuple(subchecks)
        if detail is None:
            detail = (
                "; ".join(
                    f"{subcheck.label}: {subcheck.detail}" for subcheck in subchecks
                )
                + "."
            )
        return CheckResult(cls.key, cls.label, detail, subchecks)

    @classmethod
    def ttl_subcheck(
        cls,
        label: str,
        name: str,
        record_type: dns.rdatatype.RdataType,
        lookup: Lookup,
    ) -> SubCheck:
        """Grade a record's TTL against the shared minimum."""
        ttl = lookup.ttl(name, record_type)
        if ttl is None:
            return SubCheck(label, "skip", "No TTL reported")
        if ttl + cls.TTL_TOLERANCE_SECS >= cls.TTL_MIN_SECS:
            return SubCheck(label, "pass", f"{ttl}s TTL")
        return SubCheck(label, "fail", f"{ttl}s TTL", severity="weak")

    @classmethod
    def is_global_address(cls, address: str) -> bool:
        """Reject addresses that are private or belong to a transition range."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return ip.is_global and not (
            isinstance(ip, ipaddress.IPv6Address)
            and (
                ip.ipv4_mapped is not None
                or any(ip in network for network in cls.TRANSITION_NETWORKS)
            )
        )


class MxCheck(Check):
    """Grade the MX records and their TTL."""

    key = "mx"
    label = "MX"
    slug = "mx"
    hints = {
        "MX record": "Publish an MX record that points at the server that receives mail for this domain.",
    }
    MAX_MX_EXCHANGES = 5

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        mx = lookup.mx(name)
        if mx.failed:
            record = SubCheck("MX record", "skip", "Lookup failed")
        elif mx.null:
            record = SubCheck("MX record", "pass", "Null MX, no mail is received")
        elif not mx.exchanges:
            record = SubCheck("MX record", "fail", "No MX record", severity="blocking")
        else:
            exchanges = mx.exchanges[: cls.MAX_MX_EXCHANGES]
            detail = ", ".join(exchanges)
            if len(mx.exchanges) > cls.MAX_MX_EXCHANGES:
                detail += f" (+{len(mx.exchanges) - cls.MAX_MX_EXCHANGES} more)"
            record = SubCheck("MX record", "pass", detail)
        subchecks = [record]
        if record.status == "pass":
            subchecks.append(cls.ttl_subcheck("MX TTL", name, dns.rdatatype.MX, lookup))
        return cls.result(subchecks)


@dataclasses.dataclass(frozen=True, slots=True)
class SpfLookup:
    records: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    exact: tuple[str, ...] = ()
    lookups: int = 0
    sampled: int = 0
    exhausted: bool = False
    error: bool = False


@dataclasses.dataclass(slots=True)
class SpfWalk:
    """Follow an SPF record graph and collect the addresses it authorizes."""

    lookup: Lookup
    visited: set[str] = dataclasses.field(default_factory=set)
    addresses: list[str] = dataclasses.field(default_factory=list)
    exact: list[str] = dataclasses.field(default_factory=list)
    lookups: int = 0
    sampled: int = 0
    exhausted: bool = False

    def walk_record(self, domain: str, record: str) -> None:
        """Walk one SPF record and count the DNS lookups it needs."""
        # Every term that triggers a query counts against the RFC 7208 limit.
        self.lookups += sum(
            token.lstrip("+-~?").split(":", 1)[0].split("=", 1)[0].lower()
            in SpfCheck.SPF_LOOKUP_TERMS
            for token in record.split()[1:]
        )
        if self.lookups > SpfCheck.SPF_MAX_LOOKUPS:
            self.exhausted = True
        else:
            for token in record.split()[1:]:
                self.walk_token(domain, token)

    def walk_token(self, domain: str, token: str) -> None:
        """Walk one SPF term."""
        token = token.lstrip("+-~?")
        if token.startswith("redirect="):
            self.follow(token.removeprefix("redirect="))
        else:
            self.walk_mechanism(domain, token)

    def walk_mechanism(self, domain: str, token: str) -> None:
        """Walk a mechanism that carries a host, a prefix, or a nested SPF record."""
        mechanism, _, argument = token.partition(":")
        match mechanism:
            case "include":
                self.follow(argument)
            case "a" | "mx" if "%" not in argument:
                host, _, prefix = argument.partition("/")
                self.add_mechanism_addresses(mechanism, host, prefix, domain)
            case "ip4" | "ip6" if "%" not in argument:
                host, slash, prefix = argument.partition("/")
                if slash:
                    self.add_network(host, prefix)
                else:
                    self.addresses.append(host)
                    self.exact.append(host)

    def follow(self, name: str) -> None:
        """Walk a nested SPF record once per name."""
        key = name.lower()
        if key not in self.visited:
            self.visited.add(key)
            records = self.lookup.text(name)
            spf_records = tuple(
                record
                for record in records or ()
                if record.lower().startswith("v=spf1")
            )
            if len(spf_records) == 1:
                self.walk_record(name, spf_records[0])

    def add_mechanism_addresses(
        self, mechanism: str, host: str, prefix: str, domain: str
    ) -> None:
        """Collect the addresses behind an a or mx mechanism."""
        names = (
            (host or domain,)
            if mechanism == "a"
            else self.lookup.mx(host or domain).exchanges
        )
        ipv4_prefix, _, ipv6_prefix = prefix.partition("/")
        ipv4_prefix = ipv4_prefix or "32"
        ipv6_prefix = ipv6_prefix.lstrip("/") or "128"
        for name in names:
            if prefix:
                for address in self.lookup.query(name, dns.rdatatype.A).records:
                    self.add_network(address, ipv4_prefix)
                for address in self.lookup.query(name, dns.rdatatype.AAAA).records:
                    self.add_network(address, ipv6_prefix)
            else:
                resolved = self.lookup.addresses(name)
                self.addresses.extend(resolved)
                self.exact.extend(resolved)

    def add_network(self, address: str, prefix: str) -> None:
        """Collect the first host of a network and sample its range."""
        try:
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        except ValueError:
            network = None
        if network is not None:
            host = network.network_address
            if network.num_addresses > 1:
                # Never probe the network address or the broadcast that closes the
                # range. The first host is the one right after the network address.
                host += 1
                self.sampled += 1
            else:
                self.exact.append(str(host))
            self.addresses.append(str(host))


class SpfCheck(Check):
    """Grade the SPF record, its lookup budget, and the addresses it authorizes."""

    key = "spf"
    label = "SPF"
    slug = "spf"
    hints = {
        "SPF record": "Publish exactly one TXT record at the domain root that starts with v=spf1.",
        "Lookup limit": "Cut include:, a:, and mx: terms until the record needs at most 10 DNS lookups.",
        "Strict all": "End the SPF record with -all instead of ~all.",
        "Reverse DNS": "Point each sender address's PTR record at a hostname that resolves back to the same address.",
    }
    SPF_MAX_LOOKUPS = 10
    SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
    REVERSE_DNS_WORKERS = 16

    @classmethod
    def resolve(cls, name: str, lookup: Lookup) -> SpfLookup:
        """Collect the SPF records and the addresses they authorize."""
        records = lookup.text(name)
        if records is None:
            return SpfLookup(error=True)
        spf_records = tuple(
            record for record in records if record.lower().startswith("v=spf1")
        )
        if len(spf_records) != 1:
            return SpfLookup(records=spf_records)
        walk = SpfWalk(lookup, visited={name.lower()})
        walk.walk_record(name, spf_records[0])
        return SpfLookup(
            records=spf_records,
            addresses=tuple(
                address
                for address in dict.fromkeys(walk.addresses)
                if cls.is_global_address(address)
            ),
            exact=tuple(
                address
                for address in dict.fromkeys(walk.exact)
                if cls.is_global_address(address)
            ),
            lookups=walk.lookups,
            sampled=walk.sampled,
            exhausted=walk.exhausted,
        )

    @classmethod
    def skipped(cls, detail: str) -> Iterator[SubCheck]:
        """Yield the subchecks that cannot run without a usable SPF record."""
        yield SubCheck("Lookup limit", "skip", detail)
        yield SubCheck("Strict all", "skip", detail, severity="weak")

    @classmethod
    def qualifier(cls, record: str) -> str:
        """Return the qualifier of the all mechanism."""
        token = next(
            (
                item
                for item in record.split()[1:]
                if item.lstrip("+-~?").lower() == "all"
            ),
            None,
        )
        if token is None:
            return ""
        return token[0] if token[0] in "+-~?" else "+"

    @classmethod
    def reverse_dns(cls, spf: SpfLookup, lookup: Lookup) -> SubCheck:
        """Grade the reverse DNS of every exact SPF address."""
        if not spf.addresses:
            return SubCheck("Reverse DNS", "skip", "No SPF address", severity="weak")
        if not spf.exact:
            return SubCheck(
                "Reverse DNS", "skip", "SPF covers ranges only", severity="weak"
            )
        addresses = spf.exact
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=cls.REVERSE_DNS_WORKERS
        ) as executor:
            matches = list(
                executor.map(
                    functools.partial(cls.has_matching_reverse_dns, lookup=lookup),
                    addresses,
                )
            )
        checked = [
            address
            for address, matched in zip(addresses, matches)
            if matched is not None
        ]
        if not checked:
            return SubCheck(
                "Reverse DNS", "skip", "No reverse DNS answer", severity="weak"
            )
        mismatched = [
            address for address, matched in zip(addresses, matches) if matched is False
        ]
        detail = (
            f"{len(checked) - len(mismatched)} of {len(checked)} "
            "addresses point at a hostname that resolves back"
        )
        return SubCheck(
            "Reverse DNS",
            "fail" if mismatched else "pass",
            detail,
            severity="weak",
            addresses=tuple(mismatched[: cls.MAX_LISTED_ADDRESSES]),
        )

    @classmethod
    def has_matching_reverse_dns(cls, address: str, lookup: Lookup) -> bool | None:
        """Report whether a PTR name resolves back to the address."""
        names = lookup.ptr(address)
        if names is None:
            return None
        target = ipaddress.ip_address(address)
        return any(
            target in map(ipaddress.ip_address, lookup.addresses(name))
            for name in names
        )

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        spf = cls.resolve(name, lookup)
        if spf.error:
            return cls.result(
                [
                    SubCheck("SPF record", "skip", "Lookup failed"),
                    *cls.skipped("Lookup failed"),
                ],
                detail="Lookup failed.",
            )
        if not spf.records:
            detail = "No SPF record"
            return cls.result(
                [
                    SubCheck("SPF record", "fail", detail, severity="blocking"),
                    *cls.skipped(detail),
                ],
                detail=f"{detail}.",
            )
        if len(spf.records) > 1:
            detail = f"{len(spf.records)} SPF records (permerror)."
            return cls.result(
                [
                    SubCheck("SPF record", "fail", detail, severity="blocking"),
                    *cls.skipped("Multiple SPF records"),
                ],
                detail=detail,
            )
        record = spf.records[0]
        qualifier = cls.qualifier(record)
        subchecks = (
            SubCheck("SPF record", "pass", "1 record"),
            SubCheck(
                "Lookup limit",
                "fail" if spf.exhausted else "pass",
                f"{spf.lookups} DNS lookup{'s' if spf.lookups != 1 else ''} (limit {cls.SPF_MAX_LOOKUPS})",
                severity="blocking",
            ),
            SubCheck(
                "Strict all",
                "pass" if qualifier == "-" else "fail",
                f"{qualifier}all" if qualifier else "No all mechanism",
                severity="weak",
            ),
            cls.reverse_dns(spf, lookup),
            cls.ttl_subcheck("SPF TTL", name, dns.rdatatype.TXT, lookup),
        )
        return cls.result(subchecks)


class DmarcCheck(Check):
    """Grade the DMARC record and the policy it publishes."""

    key = "dmarc"
    label = "DMARC"
    slug = "dmarc"
    hints = {
        "DMARC record": "Publish a TXT record at _dmarc.<domain> that starts with v=DMARC1.",
        "Policy": "Set p=reject in the _dmarc record so receivers reject unauthenticated mail.",
        "Aggregate reports": "Add rua=mailto:<address> so receivers send aggregate reports.",
        "Full coverage": "Drop pct= or set pct=100 so the policy applies to every message.",
    }

    @classmethod
    def skipped(cls, detail: str) -> Iterator[SubCheck]:
        """Yield the subchecks that cannot run without a usable DMARC record."""
        yield SubCheck("Policy", "skip", detail)
        yield SubCheck("Aggregate reports", "skip", detail, severity="weak")
        yield SubCheck("Full coverage", "skip", detail, severity="weak")

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        records = lookup.text(f"_dmarc.{name}")
        policy = (
            DmarcPolicy.from_records(records)
            if records is not None
            else DmarcPolicy(temperror=True)
        )
        if policy.temperror:
            return cls.result(
                [
                    SubCheck("DMARC record", "skip", "Lookup failed"),
                    *cls.skipped("No usable DMARC record"),
                ],
                detail="DMARC lookup failed.",
            )
        if not policy.is_published:
            return cls.result(
                [
                    SubCheck(
                        "DMARC record",
                        "fail",
                        "No DMARC record",
                        severity="blocking",
                    ),
                    *cls.skipped("No usable DMARC record"),
                ],
                detail="No DMARC record.",
            )
        if policy.record_count > 1:
            detail = f"{policy.record_count} DMARC records (permerror)."
            return cls.result(
                [
                    SubCheck("DMARC record", "fail", detail, severity="blocking"),
                    *cls.skipped("No usable DMARC record"),
                ],
                detail=detail,
            )
        p = policy.p.lower()
        if p not in {"none", "quarantine", "reject"}:
            subchecks = (
                SubCheck("DMARC record", "pass", "1 record"),
                SubCheck("Policy", "fail", "No valid p tag", severity="blocking"),
                *(
                    SubCheck(label, "skip", "No valid DMARC policy", severity="weak")
                    for label in ("Aggregate reports", "Full coverage")
                ),
                cls.ttl_subcheck(
                    "DMARC TTL", f"_dmarc.{name}", dns.rdatatype.TXT, lookup
                ),
            )
            return cls.result(subchecks)
        subchecks = (
            SubCheck("DMARC record", "pass", "1 record"),
            SubCheck(
                "Policy",
                "pass" if p == "reject" else "fail",
                f"p={p}",
                severity="weak",
            ),
            SubCheck(
                "Aggregate reports",
                "pass" if policy.rua else "fail",
                policy.rua or "No rua",
                severity="weak",
            ),
            SubCheck(
                "Full coverage",
                "pass" if policy.pct == 100 else "fail",
                f"pct={policy.pct}",
                severity="weak",
            ),
            cls.ttl_subcheck("DMARC TTL", f"_dmarc.{name}", dns.rdatatype.TXT, lookup),
        )
        return cls.result(subchecks)


class MtaStsCheck(Check):
    """Grade the MTA-STS record and the policy it points at."""

    key = "mta_sts"
    label = "MTA-STS"
    slug = "mta-sts"
    hints = {
        "MTA-STS record": "Publish a TXT record at _mta-sts.<domain> that starts with v=STSv1.",
        "Policy": "Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt.",
        "Enforced mode": "Set mode: enforce in the MTA-STS policy.",
        "MX match": "List every MX host in the policy's mx: lines.",
    }
    FETCH_TIMEOUT_SECS = 5
    FETCH_CACHE_SECS = 300
    POLICY_LIMIT_BYTES = 64 * 1024

    @classmethod
    def skipped(cls) -> Iterator[SubCheck]:
        """Yield the subchecks that cannot run without a usable MTA-STS record."""
        yield SubCheck("Policy", "skip", "No usable MTA-STS record")
        yield SubCheck(
            "Enforced mode", "skip", "No usable MTA-STS record", severity="weak"
        )
        yield SubCheck("MX match", "skip", "No usable MTA-STS record")

    @classmethod
    def fetch_policy(cls, name: str, lookup: Lookup) -> dict | None:
        """Fetch and parse the policy document for the domain."""
        body = cls.fetch_body(
            f"https://mta-sts.{name}/.well-known/mta-sts.txt",
            cls.POLICY_LIMIT_BYTES,
            lookup,
        )
        return cls.parse_policy(body) if body is not None else None

    @staticmethod
    def parse_target(url: str):
        """Split the policy URL, rejecting anything that is not HTTPS."""
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return None
        if parsed.scheme != "https" or not parsed.hostname:
            return None
        return parsed, port

    @classmethod
    def fetch_netloc(
        cls, hostname: str, port: int | None, lookup: Lookup
    ) -> str | None:
        """Return the verified address and port to fetch the policy from."""
        resolved = lookup.addresses(hostname)
        if not resolved or not all(cls.is_global_address(item) for item in resolved):
            return None
        address = resolved[0]
        netloc = f"[{address}]" if ":" in address else address
        return f"{netloc}:{port}" if port else netloc

    @classmethod
    def fetch_body(cls, url: str, limit_bytes: int, lookup: Lookup) -> bytes | None:
        """Fetch a policy document over HTTPS from a global address."""
        target = cls.parse_target(url)
        if target is None:
            return None
        parsed, port = target
        cache_key = f"domain_check:fetch:{hashlib.sha256(url.encode()).hexdigest()}"
        if (cached := cache.get(cache_key)) is not None:
            return cached
        netloc = cls.fetch_netloc(parsed.hostname, port, lookup)
        if netloc is None:
            return None
        for attempt in range(Lookup.DNS_RETRIES):
            try:
                body = cls.stream_body(parsed, netloc, port, limit_bytes)
            except httpx.TransportError, httpx.TimeoutException:
                if attempt == Lookup.DNS_RETRIES - 1:
                    return None
                time.sleep(Lookup.DNS_RETRY_DELAY_SECS * 2**attempt)
            except httpx.HTTPError, httpx.InvalidURL:
                return None
            else:
                if body is not None:
                    cache.set(cache_key, body, cls.FETCH_CACHE_SECS)
                return body
        return None

    @classmethod
    def stream_body(
        cls, parsed, netloc: str, port: int | None, limit_bytes: int
    ) -> bytes | None:
        """Stream a policy body, stopping at the size limit or the deadline."""
        deadline = time.monotonic() + cls.FETCH_TIMEOUT_SECS
        headers = {"Host": f"{parsed.hostname}:{port}" if port else parsed.hostname}
        with (
            httpx.Client(
                trust_env=False, follow_redirects=False, timeout=cls.FETCH_TIMEOUT_SECS
            ) as client,
            client.stream(
                "GET",
                urlunsplit(
                    (parsed.scheme, netloc, parsed.path or "/", parsed.query, "")
                ),
                headers=headers,
                extensions={"sni_hostname": parsed.hostname},
            ) as response,
        ):
            if response.status_code != 200:
                return None
            chunks = []
            size = 0
            for chunk in response.iter_bytes():
                if time.monotonic() > deadline:
                    return None
                size += len(chunk)
                if size > limit_bytes:
                    return None
                chunks.append(chunk)
            return b"".join(chunks)

    @staticmethod
    def parse_policy(body: bytes) -> dict | None:
        """Parse an MTA-STS policy document."""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
        fields = {}
        patterns = []
        for line in text.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                key = key.strip().lower()
                value = value.strip()
                if key == "mx":
                    patterns.append(value)
                elif key in {"version", "mode", "max_age"}:
                    fields[key] = value
        try:
            max_age = int(fields.get("max_age", ""))
        except ValueError:
            return None
        mode = fields.get("mode", "").lower()
        if (
            fields.get("version") != "STSv1"
            or max_age <= 0
            or not patterns
            or mode not in {"enforce", "testing", "none"}
        ):
            return None
        return {"mode": mode, "mx": tuple(patterns)}

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        records = lookup.text(f"_mta-sts.{name}")
        if records is None:
            return cls.result(
                [
                    SubCheck("MTA-STS record", "skip", "Lookup failed"),
                    *cls.skipped(),
                ],
                detail="MTA-STS lookup failed.",
            )
        tags = next(
            (
                parsed
                for record in records
                if record.lower().startswith("v=stsv1")
                and (parsed := MtaStsRecord.parse(record))
            ),
            None,
        )
        if tags is None:
            return cls.result(
                [
                    SubCheck("MTA-STS record", "fail", "No valid MTA-STS record"),
                    *cls.skipped(),
                ],
                detail="No valid MTA-STS record.",
            )
        subchecks = [SubCheck("MTA-STS record", "pass", f"id={tags['id']}")]
        policy = cls.fetch_policy(name, lookup)
        if policy is None:
            subchecks.extend(
                (
                    SubCheck("Policy", "fail", "No fetchable policy"),
                    SubCheck(
                        "Enforced mode",
                        "skip",
                        "No fetchable policy",
                        severity="weak",
                    ),
                    SubCheck("MX match", "skip", "No fetchable policy"),
                )
            )
        else:
            subchecks.append(SubCheck("Policy", "pass", "Fetched"))
            enforced = policy["mode"] == "enforce"
            subchecks.append(
                SubCheck(
                    "Enforced mode",
                    "pass" if enforced else "fail",
                    policy["mode"],
                    severity="weak",
                )
            )
            mx = lookup.mx(name)
            if mx.failed:
                subchecks.append(SubCheck("MX match", "skip", "MX lookup failed"))
            else:
                matched = bool(mx.exchanges) and all(
                    any(
                        pattern == "*" or MtaStsRecord.matches(exchange, pattern)
                        for pattern in policy["mx"]
                    )
                    for exchange in mx.exchanges
                )
                detail = (
                    "All MX hosts match" if matched else "MX does not match the policy"
                )
                subchecks.append(
                    SubCheck("MX match", "pass" if matched else "fail", detail)
                )
        subchecks.append(
            cls.ttl_subcheck(
                "MTA-STS TTL", f"_mta-sts.{name}", dns.rdatatype.TXT, lookup
            )
        )
        return cls.result(subchecks)


class TlsRptCheck(Check):
    """Grade the TLS-RPT record and its reporting address."""

    key = "tls_rpt"
    label = "TLS-RPT"
    slug = "tls-rpt"
    hints = {
        "TLS-RPT record": "Publish a TXT record at _smtp._tls.<domain> that starts with v=TLSRPTv1.",
        "Reporting address": "Add rua=mailto:<address> to the TLS-RPT record.",
    }

    @classmethod
    def reporting_address(cls, record: str) -> str:
        """Return the rua value of a TLS-RPT record."""
        rua = ""
        for part in record.split(";"):
            key, separator, value = part.partition("=")
            if separator and key.strip().lower() == "rua":
                rua = value.strip()
        return rua

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        records = lookup.text(f"_smtp._tls.{name}")
        if records is None:
            return cls.result(
                [
                    SubCheck("TLS-RPT record", "skip", "Lookup failed"),
                    SubCheck(
                        "Reporting address",
                        "skip",
                        "No usable TLS-RPT record",
                    ),
                ],
                detail="TLS-RPT lookup failed.",
            )
        record = next(
            (item for item in records if item.lower().startswith("v=tlsrptv1")),
            None,
        )
        if record is None:
            return cls.result(
                [
                    SubCheck("TLS-RPT record", "fail", "No TLS-RPT record"),
                    SubCheck(
                        "Reporting address",
                        "skip",
                        "No TLS-RPT record",
                    ),
                ],
                detail="No TLS-RPT record.",
            )
        rua = cls.reporting_address(record)
        subchecks = (
            SubCheck("TLS-RPT record", "pass", "1 record"),
            SubCheck(
                "Reporting address",
                "pass" if rua else "fail",
                rua or "No rua",
            ),
            cls.ttl_subcheck(
                "TLS-RPT TTL", f"_smtp._tls.{name}", dns.rdatatype.TXT, lookup
            ),
        )
        return cls.result(
            subchecks,
            detail="Record with rua." if rua else "Record without rua.",
        )


@dataclasses.dataclass(frozen=True, slots=True)
class BlocklistAnswer:
    codes: tuple[str, ...] = ()
    failed: bool = False
    refused: bool = False

    @property
    def problem(self) -> str:
        if self.refused:
            return "refused the query"
        if self.failed:
            return "did not answer"
        return ""


class BlocklistsCheck(Check):
    """Grade the domain and its SPF addresses against DNS blocklists."""

    key = "blocklists"
    label = "Blocklists"
    hints = {
        "Domain blocklists": "Ask the operator to delist the domain, then fix the sending behavior that caused it.",
        "SPF address blocklists": "Ask the operator to delist the address, then fix the sending behavior that caused it.",
    }
    BLOCKLIST_WORKERS = 16
    DOMAIN_PROVIDERS = (
        BlocklistProvider(
            "Spamhaus DBL",
            "dbl.spamhaus.org",
            keyed_zone="{key}.dbl.dq.spamhaus.net",
        ),
    )
    ADDRESS_PROVIDERS = PUBLIC_ADDRESS_PROVIDERS

    @staticmethod
    def zone(provider: BlocklistProvider) -> str:
        """Return the query zone, keyed when a Spamhaus key is configured."""
        if provider.keyed_zone and settings.SPAMHAUS_KEY:
            return provider.keyed_zone.format(key=settings.SPAMHAUS_KEY)
        return provider.zone

    @staticmethod
    def resolve_codes(query: str, lookup: Lookup) -> BlocklistAnswer:
        """Resolve a blocklist query and classify the answer."""
        answer = lookup.query(query, dns.rdatatype.A)
        if answer.failed:
            return BlocklistAnswer(failed=True)
        if any(
            ipaddress.ip_address(code) in REFUSAL_NETWORK for code in answer.records
        ):
            return BlocklistAnswer(refused=True)
        return BlocklistAnswer(codes=answer.records)

    @classmethod
    def domain_listing(cls, name: str, lookup: Lookup) -> tuple[list[str], list[str]]:
        """Query every domain blocklist for the domain."""
        listed = []
        problems = []
        for provider in cls.DOMAIN_PROVIDERS:
            answer = cls.resolve_codes(f"{name}.{cls.zone(provider)}", lookup)
            if answer.problem:
                problems.append(f"{provider.name} {answer.problem}")
            elif answer.codes:
                listed.append(f"{provider.name} ({', '.join(answer.codes)})")
        return listed, problems

    @classmethod
    def address_listing(
        cls, address: str, lookup: Lookup
    ) -> tuple[list[str], list[str]]:
        """Query every address blocklist for one SPF address."""
        listed = []
        problems = []
        pointer = reverse_pointer(address)
        for provider in cls.ADDRESS_PROVIDERS:
            answer = cls.resolve_codes(f"{pointer}.{cls.zone(provider)}", lookup)
            if answer.problem:
                problems.append(f"{provider.name} {answer.problem}")
            elif answer.codes:
                listed.append(f"{provider.name} ({address})")
        return listed, problems

    @classmethod
    def run(cls, name: str, lookup: Lookup) -> CheckResult:
        spf = SpfCheck.resolve(name, lookup)
        addresses = spf.addresses
        details = []
        subchecks = []
        domain_listed, domain_problems = cls.domain_listing(name, lookup)
        if domain_listed:
            detail = f"Listed on {', '.join(domain_listed)}"
            details.append(f"Domain {detail.lower()}")
            subchecks.append(
                SubCheck("Domain blocklists", "fail", detail, severity="blocking")
            )
        elif len(domain_problems) == len(cls.DOMAIN_PROVIDERS):
            details.append("Domain blocklist lookup unavailable")
            subchecks.append(
                SubCheck("Domain blocklists", "skip", ", ".join(domain_problems))
            )
        else:
            details.append("Domain not listed")
            subchecks.append(SubCheck("Domain blocklists", "pass", "Not listed"))
        if spf.sampled:
            details.append(f"sampled {spf.sampled} network ranges")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=cls.BLOCKLIST_WORKERS
        ) as executor:
            listings = list(
                executor.map(
                    functools.partial(cls.address_listing, lookup=lookup), addresses
                )
            )
        address_listed = [*entries for entries, _ in listings]
        address_problems = [*entries for _, entries in listings]
        queries = len(addresses) * len(cls.ADDRESS_PROVIDERS)
        if address_listed:
            detail = f"Listed on {', '.join(address_listed)}"
            details.append(f"SPF address {detail.lower()}")
            subchecks.append(
                SubCheck("SPF address blocklists", "fail", detail, severity="blocking")
            )
        elif not addresses:
            details.append("SPF address not checked")
            subchecks.append(
                SubCheck("SPF address blocklists", "skip", "No SPF address")
            )
        elif len(address_problems) == queries:
            details.append("SPF address blocklist lookup unavailable")
            subchecks.append(
                SubCheck(
                    "SPF address blocklists",
                    "skip",
                    ", ".join(dict.fromkeys(address_problems)),
                )
            )
        else:
            details.append("SPF address not listed")
            count = len(addresses)
            detail = f"{count} address{'es' if count != 1 else ''} not listed"
            refused = ", ".join(dict.fromkeys(address_problems))
            if refused:
                detail += f" ({refused})"
            subchecks.append(SubCheck("SPF address blocklists", "pass", detail))
        domain_problems.extend(address_problems)
        if domain_problems:
            details.append(f"unavailable: {', '.join(dict.fromkeys(domain_problems))}")
        return cls.result(subchecks, detail=", ".join(details) + ".")


CHECKS: tuple[type[Check], ...] = (
    MxCheck,
    SpfCheck,
    DmarcCheck,
    MtaStsCheck,
    TlsRptCheck,
    BlocklistsCheck,
)
CHECK_ORDER = tuple(check.key for check in CHECKS)
CHECKS_BY_KEY = {check.key: check for check in CHECKS}
CHECK_SLUGS = {check.key: check.slug for check in CHECKS if check.slug}


def subcheck_hint(key: str, label: str) -> str:
    """Return the remediation hint for a stored subcheck."""
    check = CHECKS_BY_KEY.get(key)
    return check.hint(label) if check is not None else ""


def evaluate_domain(name: str) -> Iterator[CheckResult]:
    """Run every check against the domain."""
    lookup = Lookup()
    yield from evaluate_delivery(name, lookup)
    yield from evaluate_authentication(name, lookup)
    yield from evaluate_reputation(name, lookup)


def evaluate_delivery(name: str, lookup: Lookup) -> Iterator[CheckResult]:
    """Run the delivery checks: MX, MTA-STS, and TLS-RPT."""
    for check in (MxCheck, MtaStsCheck, TlsRptCheck):
        yield check.run(name, lookup)


def evaluate_authentication(name: str, lookup: Lookup) -> Iterator[CheckResult]:
    """Run the authentication checks: SPF and DMARC."""
    for check in (SpfCheck, DmarcCheck):
        yield check.run(name, lookup)


def evaluate_reputation(name: str, lookup: Lookup) -> Iterator[CheckResult]:
    """Run the reputation checks: blocklists."""
    yield BlocklistsCheck.run(name, lookup)
