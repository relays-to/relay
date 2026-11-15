import concurrent.futures
import dataclasses
import functools
import hashlib
import ipaddress
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
from django.conf import settings
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _

from abstract.blocklists import (
    PUBLIC_ADDRESS_PROVIDERS,
    REFUSAL_NETWORK,
    BlocklistProvider,
    reverse_pointer,
)
from abstract.mailauth import DmarcPolicy
from domains.mta_sts import matches_mta_sts_mx_pattern, parse_mta_sts_txt_record

from .lookup import (
    DNS_CACHE_SECS,
    DNS_RETRIES,
    DNS_RETRY_DELAY_SECS,
    Lookup,
    MxLookup,
)

FETCH_TIMEOUT_SECS = 5
POLICY_LIMIT_BYTES = 64 * 1024
MAX_MX_EXCHANGES = 5
SMALL_NETWORK_ADDRESSES = 256
REVERSE_DNS_WORKERS = 16
BLOCKLIST_WORKERS = 16
SPF_MAX_LOOKUPS = 10
TTL_MIN_SECS = 3600
# Resolvers return the remaining TTL, so an hour-long record can answer with
# minutes left. Absorb that countdown before calling a record too short-lived.
TTL_TOLERANCE_SECS = 300
SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
CHECK_ORDER = (
    "mx",
    "spf",
    "dmarc",
    "mta_sts",
    "tls_rpt",
    "blocklists",
)

CHECK_HINTS = {
    "mx": _(
        "Publish an MX record that points to the server that receives mail for this domain."
    ),
    "spf": _(
        "Publish one TXT record at the domain root that starts with v=spf1 and stays "
        "within 10 DNS lookups. For stricter enforcement, end it with -all."
    ),
    "dmarc": _(
        "Publish a TXT record at _dmarc that starts with v=DMARC1 and sets a valid p tag. "
        "For the strongest policy and reporting, set p=reject and add rua=."
    ),
    "mta_sts": _(
        "Publish a TXT record at _mta-sts and serve a policy at "
        "https://mta-sts.<domain>/.well-known/mta-sts.txt. Set mode: enforce "
        "for the strongest policy."
    ),
    "tls_rpt": _(
        "Publish a TXT record at _smtp._tls that starts with v=TLSRPTv1 "
        "and sets rua=mailto:<address>."
    ),
    "blocklists": _(
        "Ask the operator to delist the domain or the SPF-authorized address, "
        "then fix the sending behavior that caused the listing."
    ),
}

CHECK_SLUGS = {
    "mx": "mx",
    "spf": "spf",
    "dmarc": "dmarc",
    "mta_sts": "mta-sts",
    "tls_rpt": "tls-rpt",
}

DOMAIN_PROVIDERS = (
    BlocklistProvider(
        "Spamhaus DBL",
        "dbl.spamhaus.org",
        keyed_zone="{key}.dbl.dq.spamhaus.net",
    ),
)

TRANSITION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
)


@dataclasses.dataclass(frozen=True, slots=True)
class SubCheck:
    label: str
    status: str
    detail: str
    severity: str = "broken"


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


def summarize(subchecks: tuple[SubCheck, ...]) -> str:
    return (
        "; ".join(f"{subcheck.label}: {subcheck.detail}" for subcheck in subchecks)
        + "."
    )


@dataclasses.dataclass(frozen=True, slots=True)
class SpfLookup:
    records: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    lookups: int = 0
    sampled: int = 0
    exhausted: bool = False
    error: bool = False


@dataclasses.dataclass(slots=True)
class SpfWalker:
    visited: set[str] = dataclasses.field(default_factory=set)
    addresses: list[str] = dataclasses.field(default_factory=list)
    lookups: int = 0
    sampled: int = 0
    exhausted: bool = False


def evaluate_domain(name: str) -> list[CheckResult]:
    lookup = Lookup()
    return [
        *evaluate_delivery(name, lookup),
        *evaluate_authentication(name, lookup),
        *evaluate_reputation(name, lookup),
    ]


def evaluate_delivery(name: str, lookup: Lookup) -> list[CheckResult]:
    return [
        check_mx(name, lookup),
        check_mta_sts(name, lookup),
        check_tls_rpt(name, lookup),
    ]


def evaluate_authentication(name: str, lookup: Lookup) -> list[CheckResult]:
    return [
        check_spf(name, lookup),
        check_dmarc(name, lookup),
    ]


def evaluate_reputation(name: str, lookup: Lookup) -> list[CheckResult]:
    return [check_blocklists(name, lookup)]


def resolve_mx(name: str, lookup: Lookup) -> MxLookup:
    return lookup.mx(name)


def check_ttl(label: str, name: str, record_type: str, lookup: Lookup) -> SubCheck:
    ttl = lookup.ttl(name, record_type)
    if ttl is None:
        return SubCheck(label, "skip", "No TTL reported")
    if ttl + TTL_TOLERANCE_SECS >= TTL_MIN_SECS:
        return SubCheck(label, "pass", f"{ttl}s TTL")
    return SubCheck(
        label,
        "fail",
        f"{ttl}s TTL, raise to at least {TTL_MIN_SECS}s",
        severity="weak",
    )


def check_mx(name: str, lookup: Lookup) -> CheckResult:
    mx = resolve_mx(name, lookup)
    if mx.failed:
        record = SubCheck("MX record", "skip", "Lookup failed")
    elif mx.null:
        record = SubCheck("MX record", "pass", "Null MX, no mail is received")
    elif not mx.exchanges:
        record = SubCheck("MX record", "fail", "No MX record", severity="blocking")
    else:
        exchanges = mx.exchanges[:MAX_MX_EXCHANGES]
        detail = ", ".join(exchanges)
        if len(mx.exchanges) > MAX_MX_EXCHANGES:
            detail += f" (+{len(mx.exchanges) - MAX_MX_EXCHANGES} more)"
        record = SubCheck("MX record", "pass", detail)
    subchecks = [record]
    if record.status == "pass":
        subchecks.append(check_ttl("MX TTL", name, "MX", lookup))
    return CheckResult("mx", "MX", summarize(tuple(subchecks)), tuple(subchecks))


def resolve_txt(name: str, lookup: Lookup) -> tuple[str, ...] | None:
    return lookup.text(name)


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        key, separator, value = part.partition("=")
        if separator:
            tags[key.strip().lower()] = value.strip()
    return tags


def count_spf_lookups(record: str) -> int:
    return sum(
        token.lstrip("+-~?").split(":", 1)[0].split("=", 1)[0].lower()
        in SPF_LOOKUP_TERMS
        for token in record.split()[1:]
    )


def spf_qualifier(record: str) -> str:
    token = next(
        (t for t in record.split()[1:] if t.lstrip("+-~?").lower() == "all"),
        None,
    )
    if token is None:
        return ""
    return token[0] if token[0] in "+-~?" else "+"


def resolve_spf(name: str, lookup: Lookup) -> SpfLookup:
    records = resolve_txt(name, lookup)
    if records is None:
        return SpfLookup(error=True)
    spf_records = tuple(
        record for record in records if record.lower().startswith("v=spf1")
    )
    if len(spf_records) != 1:
        return SpfLookup(records=spf_records)
    walker = SpfWalker(visited={name.lower()})
    walk_record(name, spf_records[0], walker, lookup)
    return SpfLookup(
        records=spf_records,
        addresses=tuple(
            address
            for address in dict.fromkeys(walker.addresses)
            if is_global_address(address)
        ),
        lookups=walker.lookups,
        sampled=walker.sampled,
        exhausted=walker.exhausted,
    )


def parse_network(address: str, prefix: str):
    try:
        return ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return None


def add_network(walker: SpfWalker, address: str, prefix: str) -> None:
    network = parse_network(address, prefix)
    if network is not None and network.num_addresses <= SMALL_NETWORK_ADDRESSES:
        walker.addresses.extend(map(str, network))
    elif network is not None:
        walker.sampled += 1
        start = network.network_address
        span = int(network.broadcast_address) - int(start)
        walker.addresses.extend(str(start + offset) for offset in (0, span // 2, span))


def add_mechanism_addresses(
    mechanism: str,
    host: str,
    prefix: str,
    domain: str,
    walker: SpfWalker,
    lookup: Lookup,
) -> None:
    names = (
        (host or domain,)
        if mechanism == "a"
        else resolve_mx(host or domain, lookup).exchanges
    )
    ipv4_prefix, _, ipv6_prefix = prefix.partition("/")
    ipv4_prefix = ipv4_prefix or "32"
    ipv6_prefix = ipv6_prefix.lstrip("/") or "128"
    for name in names:
        if not prefix:
            walker.addresses.extend(resolve_addresses(name, lookup))
            continue
        for address in lookup.query(name, "A").records:
            add_network(walker, address, ipv4_prefix)
        for address in lookup.query(name, "AAAA").records:
            add_network(walker, address, ipv6_prefix)


def walk_record(domain: str, record: str, walker: SpfWalker, lookup: Lookup) -> None:
    walker.lookups += count_spf_lookups(record)
    if walker.lookups > SPF_MAX_LOOKUPS:
        walker.exhausted = True
    else:
        for token in record.split()[1:]:
            walk_token(domain, token, walker, lookup)


def walk_token(domain: str, token: str, walker: SpfWalker, lookup: Lookup) -> None:
    token = token.lstrip("+-~?")
    if token.startswith("redirect="):
        follow_spf(token.removeprefix("redirect="), walker, lookup)
    else:
        walk_mechanism(domain, token, walker, lookup)


def walk_mechanism(domain: str, token: str, walker: SpfWalker, lookup: Lookup) -> None:
    mechanism, _, argument = token.partition(":")
    match mechanism:
        case "include":
            follow_spf(argument, walker, lookup)
        case "a" | "mx" if "%" not in argument:
            host, _, prefix = argument.partition("/")
            add_mechanism_addresses(mechanism, host, prefix, domain, walker, lookup)
        case "ip4" | "ip6" if "%" not in argument:
            host, slash, prefix = argument.partition("/")
            if slash:
                add_network(walker, host, prefix)
            else:
                walker.addresses.append(host)


def follow_spf(name: str, walker: SpfWalker, lookup: Lookup) -> None:
    key = name.lower()
    if key not in walker.visited:
        walker.visited.add(key)
        records = resolve_txt(name, lookup)
        spf_records = tuple(
            record for record in records or () if record.lower().startswith("v=spf1")
        )
        if len(spf_records) == 1:
            walk_record(name, spf_records[0], walker, lookup)


def has_matching_reverse_dns(address: str, lookup: Lookup) -> bool | None:
    names = lookup.ptr(address)
    if names is None:
        return None
    target = ipaddress.ip_address(address)
    return any(
        target in map(ipaddress.ip_address, lookup.addresses(name)) for name in names
    )


def check_reverse_dns(addresses: tuple[str, ...], lookup: Lookup) -> SubCheck:
    if not addresses:
        return SubCheck("Reverse DNS", "skip", "No SPF address", severity="weak")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=REVERSE_DNS_WORKERS
    ) as executor:
        matches = list(
            executor.map(
                functools.partial(has_matching_reverse_dns, lookup=lookup), addresses
            )
        )
    checked = [
        address for address, matched in zip(addresses, matches) if matched is not None
    ]
    if not checked:
        return SubCheck("Reverse DNS", "skip", "No reverse DNS answer", severity="weak")
    mismatched = [
        address for address, matched in zip(addresses, matches) if matched is False
    ]
    detail = (
        f"{len(checked) - len(mismatched)} of {len(checked)} "
        "addresses have a matching PTR"
    )
    if mismatched:
        detail += f"; unmatched {', '.join(mismatched[:2])}"
    return SubCheck(
        "Reverse DNS",
        "fail" if mismatched else "pass",
        detail,
        severity="weak",
    )


def check_spf(name: str, lookup: Lookup) -> CheckResult:
    spf = resolve_spf(name, lookup)
    if spf.error:
        return CheckResult(
            "spf",
            "SPF",
            "Lookup failed.",
            (
                SubCheck("SPF record", "skip", "Lookup failed"),
                SubCheck("Lookup limit", "skip", "Lookup failed"),
                SubCheck("Strict all", "skip", "Lookup failed", severity="weak"),
            ),
        )
    if not spf.records:
        detail = "No SPF record"
        skipped = (
            SubCheck("Lookup limit", "skip", detail),
            SubCheck("Strict all", "skip", detail, severity="weak"),
        )
        return CheckResult(
            "spf",
            "SPF",
            detail + ".",
            (
                SubCheck("SPF record", "fail", detail, severity="blocking"),
                *skipped,
            ),
        )
    if len(spf.records) > 1:
        detail = f"{len(spf.records)} SPF records (permerror)."
        skipped = (
            SubCheck("Lookup limit", "skip", "Multiple SPF records"),
            SubCheck("Strict all", "skip", "Multiple SPF records", severity="weak"),
        )
        return CheckResult(
            "spf",
            "SPF",
            detail,
            (
                SubCheck("SPF record", "fail", detail, severity="blocking"),
                *skipped,
            ),
        )
    record = spf.records[0]
    qualifier = spf_qualifier(record)
    all_mechanism = f"{qualifier}all" if qualifier else "No all mechanism"
    subchecks = (
        SubCheck("SPF record", "pass", "1 record"),
        SubCheck(
            "Lookup limit",
            "fail" if spf.exhausted else "pass",
            f"{spf.lookups} DNS lookup{'s' if spf.lookups != 1 else ''} (limit {SPF_MAX_LOOKUPS})",
            severity="blocking",
        ),
        SubCheck(
            "Strict all",
            "pass" if qualifier == "-" else "fail",
            all_mechanism,
            severity="weak",
        ),
        check_reverse_dns(spf.addresses, lookup),
        check_ttl("SPF TTL", name, "TXT", lookup),
    )
    return CheckResult("spf", "SPF", summarize(subchecks), subchecks)


def check_dmarc(name: str, lookup: Lookup) -> CheckResult:
    records = lookup.text(f"_dmarc.{name}")
    policy = (
        DmarcPolicy.from_records(records)
        if records is not None
        else DmarcPolicy(temperror=True)
    )
    skipped = (
        SubCheck("Policy", "skip", "No usable DMARC record"),
        *(
            SubCheck(label, "skip", "No usable DMARC record", severity="weak")
            for label in ("Aggregate reports", "Full coverage")
        ),
    )
    if policy.temperror:
        return CheckResult(
            "dmarc",
            "DMARC",
            "DMARC lookup failed.",
            (SubCheck("DMARC record", "skip", "Lookup failed"), *skipped),
        )
    if not policy.is_published:
        return CheckResult(
            "dmarc",
            "DMARC",
            "No DMARC record.",
            (
                SubCheck(
                    "DMARC record",
                    "fail",
                    "No DMARC record",
                    severity="blocking",
                ),
                *skipped,
            ),
        )
    if policy.record_count > 1:
        detail = f"{policy.record_count} DMARC records (permerror)."
        return CheckResult(
            "dmarc",
            "DMARC",
            detail,
            (
                SubCheck("DMARC record", "fail", detail, severity="blocking"),
                *skipped,
            ),
        )
    record = SubCheck("DMARC record", "pass", "1 record")
    p = policy.p.lower()
    if p not in {"none", "quarantine", "reject"}:
        subchecks = (
            record,
            SubCheck("Policy", "fail", "No valid p tag", severity="blocking"),
            SubCheck(
                "Aggregate reports",
                "skip",
                "No valid DMARC policy",
                severity="weak",
            ),
            SubCheck(
                "Full coverage",
                "skip",
                "No valid DMARC policy",
                severity="weak",
            ),
            check_ttl("DMARC TTL", f"_dmarc.{name}", "TXT", lookup),
        )
        return CheckResult("dmarc", "DMARC", summarize(subchecks), subchecks)
    subchecks = (
        record,
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
        check_ttl("DMARC TTL", f"_dmarc.{name}", "TXT", lookup),
    )
    return CheckResult("dmarc", "DMARC", summarize(subchecks), subchecks)


def check_mta_sts(name: str, lookup: Lookup) -> CheckResult:
    records = resolve_txt(f"_mta-sts.{name}", lookup)
    skipped = (
        SubCheck("Policy", "skip", "No usable MTA-STS record"),
        SubCheck("Enforced mode", "skip", "No usable MTA-STS record", severity="weak"),
        SubCheck("MX match", "skip", "No usable MTA-STS record"),
    )
    if records is None:
        return CheckResult(
            "mta_sts",
            "MTA-STS",
            "MTA-STS lookup failed.",
            (
                SubCheck("MTA-STS record", "skip", "Lookup failed"),
                *skipped,
            ),
        )
    tags = next(
        (
            parsed
            for record in records
            if record.lower().startswith("v=stsv1")
            and (parsed := parse_mta_sts_txt_record(record))
        ),
        None,
    )
    if tags is None:
        return CheckResult(
            "mta_sts",
            "MTA-STS",
            "No valid MTA-STS record.",
            (
                SubCheck(
                    "MTA-STS record",
                    "fail",
                    "No valid MTA-STS record",
                ),
                *skipped,
            ),
        )
    subchecks = [SubCheck("MTA-STS record", "pass", f"id={tags['id']}")]
    policy = fetch_policy(name, lookup)
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
        mx = resolve_mx(name, lookup)
        if mx.failed:
            subchecks.append(SubCheck("MX match", "skip", "MX lookup failed"))
        else:
            matched = allows_exchanges(mx.exchanges, policy["mx"])
            subchecks.append(
                SubCheck(
                    "MX match",
                    "pass" if matched else "fail",
                    "All MX hosts match" if matched else "MX does not match the policy",
                )
            )
    subchecks.append(check_ttl("MTA-STS TTL", f"_mta-sts.{name}", "TXT", lookup))
    subchecks = tuple(subchecks)
    return CheckResult("mta_sts", "MTA-STS", summarize(subchecks), subchecks)


def parse_target(url: str, schemes: tuple[str, ...]):
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in schemes or not parsed.hostname:
        return None
    return parsed, port


def read_body(response, limit_bytes: int, deadline: float) -> bytes | None:
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


def stream_body(
    parsed, netloc: str, port: int | None, limit_bytes: int
) -> bytes | None:
    deadline = time.monotonic() + FETCH_TIMEOUT_SECS
    headers = {"Host": f"{parsed.hostname}:{port}" if port else parsed.hostname}
    extensions = {"sni_hostname": parsed.hostname} if parsed.scheme == "https" else {}
    with (
        httpx.Client(
            trust_env=False, follow_redirects=False, timeout=FETCH_TIMEOUT_SECS
        ) as client,
        client.stream(
            "GET",
            urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, "")),
            headers=headers,
            extensions=extensions,
        ) as response,
    ):
        if response.status_code != 200:
            return None
        return read_body(response, limit_bytes, deadline)


def fetch_url(
    url: str,
    limit_bytes: int,
    lookup: Lookup,
    schemes: tuple[str, ...] = ("https",),
) -> bytes | None:
    target = parse_target(url, schemes)
    if target is None:
        return None
    parsed, port = target
    cache_key = f"domain_check:fetch:{hashlib.sha256(url.encode()).hexdigest()}"
    if (cached := cache.get(cache_key)) is not None:
        return cached
    address = next(iter(resolve_global_addresses(parsed.hostname, lookup)), None)
    if address is None:
        return None
    netloc = f"[{address}]" if ":" in address else address
    if port:
        netloc += f":{port}"
    for attempt in range(DNS_RETRIES):
        try:
            body = stream_body(parsed, netloc, port, limit_bytes)
        except httpx.TransportError, httpx.TimeoutException:
            if attempt == DNS_RETRIES - 1:
                return None
            time.sleep(DNS_RETRY_DELAY_SECS * 2**attempt)
            continue
        except httpx.HTTPError, httpx.InvalidURL:
            return None
        if body is not None:
            cache.set(cache_key, body, DNS_CACHE_SECS)
        return body
    return None


def fetch_policy(name: str, lookup: Lookup) -> dict | None:
    body = fetch_url(
        f"https://mta-sts.{name}/.well-known/mta-sts.txt",
        POLICY_LIMIT_BYTES,
        lookup,
    )
    return parse_policy(body) if body is not None else None


def is_global_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_global and not (
        isinstance(ip, ipaddress.IPv6Address)
        and (
            ip.ipv4_mapped is not None
            or any(ip in network for network in TRANSITION_NETWORKS)
        )
    )


def resolve_addresses(host: str, lookup: Lookup) -> tuple[str, ...]:
    return lookup.addresses(host)


def resolve_global_addresses(host: str, lookup: Lookup) -> tuple[str, ...]:
    addresses = resolve_addresses(host, lookup)
    return (
        addresses
        if addresses and all(is_global_address(address) for address in addresses)
        else ()
    )


def parse_policy(body: bytes) -> dict | None:
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


def allows_exchanges(exchanges: tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    return bool(exchanges) and all(
        any(
            pattern == "*" or matches_mta_sts_mx_pattern(exchange, pattern)
            for pattern in patterns
        )
        for exchange in exchanges
    )


def check_tls_rpt(name: str, lookup: Lookup) -> CheckResult:
    records = resolve_txt(f"_smtp._tls.{name}", lookup)
    if records is None:
        return CheckResult(
            "tls_rpt",
            "TLS-RPT",
            "TLS-RPT lookup failed.",
            (
                SubCheck("TLS-RPT record", "skip", "Lookup failed"),
                SubCheck(
                    "Reporting address",
                    "skip",
                    "No usable TLS-RPT record",
                ),
            ),
        )
    record = next(
        (record for record in records if record.lower().startswith("v=tlsrptv1")),
        None,
    )
    if record is None:
        return CheckResult(
            "tls_rpt",
            "TLS-RPT",
            "No TLS-RPT record.",
            (
                SubCheck("TLS-RPT record", "fail", "No TLS-RPT record"),
                SubCheck(
                    "Reporting address",
                    "skip",
                    "No TLS-RPT record",
                ),
            ),
        )
    rua = parse_tags(record).get("rua", "")
    subchecks = (
        SubCheck("TLS-RPT record", "pass", "1 record"),
        SubCheck(
            "Reporting address",
            "pass" if rua else "fail",
            rua or "No rua",
        ),
        check_ttl("TLS-RPT TTL", f"_smtp._tls.{name}", "TXT", lookup),
    )
    return CheckResult(
        "tls_rpt",
        "TLS-RPT",
        "Record with rua." if rua else "Record without rua.",
        subchecks,
    )


def check_blocklists(name: str, lookup: Lookup) -> CheckResult:
    spf = resolve_spf(name, lookup)
    addresses = spf.addresses
    details = []
    subchecks = []
    listed, problems = lookup_domain_listing(name, lookup)
    if listed:
        detail = f"Listed on {', '.join(listed)}"
        details.append(f"Domain {detail.lower()}")
        subchecks.append(
            SubCheck("Domain blocklists", "fail", detail, severity="blocking")
        )
    elif len(problems) == len(DOMAIN_PROVIDERS):
        details.append("Domain blocklist lookup unavailable")
        subchecks.append(SubCheck("Domain blocklists", "skip", ", ".join(problems)))
    else:
        details.append("Domain not listed")
        subchecks.append(SubCheck("Domain blocklists", "pass", "Not listed"))
    if spf.sampled:
        details.append(f"sampled {spf.sampled} network ranges")
    listed, address_problems = lookup_address_listings(addresses, lookup)
    queries = len(addresses) * len(PUBLIC_ADDRESS_PROVIDERS)
    if listed:
        detail = f"Listed on {', '.join(listed)}"
        details.append(f"SPF address {detail.lower()}")
        subchecks.append(
            SubCheck("SPF address blocklists", "fail", detail, severity="blocking")
        )
    elif not addresses:
        details.append("SPF address not checked")
        subchecks.append(SubCheck("SPF address blocklists", "skip", "No SPF address"))
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
    problems.extend(address_problems)
    if problems:
        details.append(f"unavailable: {', '.join(dict.fromkeys(problems))}")
    return CheckResult(
        "blocklists", "Blocklists", ", ".join(details) + ".", tuple(subchecks)
    )


def blocklist_zone(provider: BlocklistProvider) -> str:
    if provider.keyed_zone and settings.SPAMHAUS_KEY:
        return provider.keyed_zone.format(key=settings.SPAMHAUS_KEY)
    return provider.zone


def lookup_domain_listing(name: str, lookup: Lookup) -> tuple[list[str], list[str]]:
    listed = []
    problems = []
    for provider in DOMAIN_PROVIDERS:
        answer = resolve_blocklist_codes(f"{name}.{blocklist_zone(provider)}", lookup)
        if answer.problem:
            problems.append(f"{provider.name} {answer.problem}")
        elif answer.codes:
            listed.append(f"{provider.name} ({', '.join(answer.codes)})")
    return listed, problems


def lookup_address_listing(address: str, lookup: Lookup) -> tuple[list[str], list[str]]:
    listed = []
    problems = []
    pointer = reverse_pointer(address)
    for provider in PUBLIC_ADDRESS_PROVIDERS:
        answer = resolve_blocklist_codes(
            f"{pointer}.{blocklist_zone(provider)}", lookup
        )
        if answer.problem:
            problems.append(f"{provider.name} {answer.problem}")
        elif answer.codes:
            listed.append(f"{provider.name} ({address})")
    return listed, problems


def lookup_address_listings(
    addresses: tuple[str, ...], lookup: Lookup
) -> tuple[list[str], list[str]]:
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=BLOCKLIST_WORKERS
    ) as executor:
        results = list(
            executor.map(
                functools.partial(lookup_address_listing, lookup=lookup), addresses
            )
        )
    return (
        [*listed for listed, _ in results],
        [*problems for _, problems in results],
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


def resolve_blocklist_codes(query: str, lookup: Lookup) -> BlocklistAnswer:
    answer = lookup.query(query, "A")
    if answer.failed:
        return BlocklistAnswer(failed=True)
    if any(ipaddress.ip_address(code) in REFUSAL_NETWORK for code in answer.records):
        return BlocklistAnswer(refused=True)
    return BlocklistAnswer(codes=answer.records)
