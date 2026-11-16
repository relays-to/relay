import datetime
import ipaddress

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import httpx
import pytest
from django.core.cache import cache

from abstract.blocklists import (
    PUBLIC_ADDRESS_PROVIDERS,
    REFUSAL_NETWORK,
    BlocklistProvider,
    reverse_pointer,
)
from domains.check import evaluation
from domains.check.evaluation import (
    BlocklistAnswer,
    BlocklistsCheck,
    Check,
    CheckResult,
    DmarcCheck,
    MtaStsCheck,
    MxCheck,
    SpfCheck,
    SpfLookup,
    SubCheck,
    TlsRptCheck,
)
from domains.check.lookup import Lookup

CONNECTION_REFUSED = "connection refused"
INVALID_URL = "bad url"


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()


@pytest.fixture(autouse=True)
def no_zone(monkeypatch):
    def zone_for_name(name, resolver=None):
        raise dns.exception.DNSException()

    monkeypatch.setattr(dns.resolver, "zone_for_name", zone_for_name)


@pytest.fixture
def lookup(dns_resolver):
    return Lookup()


@pytest.fixture
def http(monkeypatch):
    def install(handler):
        transport = httpx.MockTransport(handler)
        real_client = httpx.Client

        def client(**kwargs):
            return real_client(transport=transport, **kwargs)

        monkeypatch.setattr(evaluation.httpx, "Client", client)

    return install


class TtlLookup:
    def __init__(self, ttl):
        self._ttl = ttl

    def ttl(self, name, record_type):
        return self._ttl


class TestSubCheckStatus:
    def test_status__fail_for_a_broken_failure(self):
        result = CheckResult("k", "L", "d", (SubCheck("a", "fail", ""),))

        assert result.status == "fail"

    def test_status__partial_for_only_weak_failures(self):
        result = CheckResult(
            "k", "L", "d", (SubCheck("a", "fail", "", severity="weak"),)
        )

        assert result.status == "partial"

    def test_status__pass_for_a_pass_without_failures(self):
        result = CheckResult("k", "L", "d", (SubCheck("a", "pass", ""),))

        assert result.status == "pass"

    def test_status__partial_when_every_subcheck_is_skipped(self):
        result = CheckResult("k", "L", "d", (SubCheck("a", "skip", ""),))

        assert result.status == "partial"


class TestCheck:
    def test_run__is_abstract(self):
        with pytest.raises(NotImplementedError):
            Check.run("example.com", None)

    def test_hint__returns_the_ttl_hint_for_a_ttl_label(self):
        assert Check.hint("MX TTL") == Check.TTL_HINT

    def test_hint__returns_the_check_hint(self):
        assert MxCheck.hint("MX record") == MxCheck.HINTS["MX record"]

    def test_hint__returns_an_empty_string_for_an_unknown_label(self):
        assert MxCheck.hint("Unknown") == ""

    def test_evaluate__yields_every_check_in_order(self, dns_resolver):
        results = list(Check.evaluate("example.com"))

        assert [result.key for result in results] == list(Check.order())
        assert all(isinstance(result, CheckResult) for result in results)

    def test_by_key__finds_a_check(self):
        assert Check.by_key("mx") is MxCheck

    def test_by_key__returns_none_for_an_unknown_key(self):
        assert Check.by_key("unknown") is None

    def test_order__lists_every_key(self):
        assert Check.order() == (
            "mx",
            "spf",
            "dmarc",
            "mta_sts",
            "tls_rpt",
            "blocklists",
        )

    def test_slugs__skips_a_check_without_a_slug(self):
        assert Check.slugs() == {
            "mx": "mx",
            "spf": "spf",
            "dmarc": "dmarc",
            "mta_sts": "mta-sts",
            "tls_rpt": "tls-rpt",
        }

    def test_hint_for__returns_the_check_hint(self):
        assert Check.hint_for("mx", "MX record") == MxCheck.HINTS["MX record"]

    def test_hint_for__returns_an_empty_string_for_an_unknown_check(self):
        assert Check.hint_for("unknown", "MX record") == ""

    def test_result__summarizes_the_subchecks(self):
        result = MxCheck.result(
            [SubCheck("one", "pass", "1"), SubCheck("two", "fail", "2")]
        )

        assert result.detail == "one: 1; two: 2."

    def test_result__keeps_an_explicit_detail(self):
        result = MxCheck.result([SubCheck("one", "pass", "1")], detail="custom")

        assert result.detail == "custom"


class TestTtlSubcheck:
    def test_ttl_subcheck__skips_a_missing_ttl(self):
        subcheck = Check.ttl_subcheck(
            "MX TTL", "example.com", dns.rdatatype.MX, TtlLookup(None)
        )

        assert subcheck == SubCheck("MX TTL", "skip", "No TTL reported")

    def test_ttl_subcheck__bumps_a_record_one_second_short(self):
        subcheck = Check.ttl_subcheck(
            "MX TTL",
            "example.com",
            dns.rdatatype.MX,
            TtlLookup(datetime.timedelta(seconds=1799)),
        )

        assert subcheck.status == "pass"

    def test_ttl_subcheck__passes_within_the_tolerance(self):
        subcheck = Check.ttl_subcheck(
            "MX TTL",
            "example.com",
            dns.rdatatype.MX,
            TtlLookup(datetime.timedelta(minutes=25)),
        )

        assert subcheck.status == "pass"

    def test_ttl_subcheck__fails_below_the_tolerance_as_weak(self):
        subcheck = Check.ttl_subcheck(
            "MX TTL",
            "example.com",
            dns.rdatatype.MX,
            TtlLookup(datetime.timedelta(minutes=24)),
        )

        assert subcheck.status == "fail"
        assert subcheck.severity == "weak"


class TestIsGlobalAddress:
    def test_is_global_address__rejects_a_non_address(self):
        assert not Check.is_global_address("not an address")

    def test_is_global_address__accepts_a_global_address(self):
        assert Check.is_global_address("8.8.8.8")

    def test_is_global_address__rejects_a_private_address(self):
        assert not Check.is_global_address("192.168.0.1")

    def test_is_global_address__rejects_an_ipv4_mapped_address(self):
        assert not Check.is_global_address("::ffff:8.8.8.8")

    @pytest.mark.parametrize(
        "address",
        ["64:ff9b::808:808", "64:ff9b:1::808:808", "2002:808:808::1", "2001::1"],
    )
    def test_is_global_address__rejects_a_transition_address(self, address):
        assert not Check.is_global_address(address)

    def test_is_global_address__accepts_a_global_ipv6_address(self):
        assert Check.is_global_address("2001:4860:4860::8888")


class TestMxCheck:
    def test_run__skips_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "MX", dns.exception.DNSException())

        result = MxCheck.run("example.com", lookup)

        assert result.subchecks == (SubCheck("MX record", "skip", "Lookup failed"),)
        assert result.status == "partial"

    def test_run__passes_a_null_mx(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "MX", "0 .")

        result = MxCheck.run("example.com", lookup)

        assert result.subchecks[0].status == "pass"
        assert result.subchecks[0].detail == "Null MX, no mail is received"
        assert result.subchecks[1].label == "MX TTL"

    def test_run__fails_without_an_mx_record(self, lookup):
        result = MxCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("MX record", "fail", "No MX record", severity="blocking"),
        )
        assert result.status == "fail"

    def test_run__lists_the_exchanges(self, lookup, dns_resolver):
        dns_resolver.add(
            "example.com", "MX", "10 mx1.example.com.", "20 mx2.example.com."
        )

        result = MxCheck.run("example.com", lookup)

        assert result.subchecks[0].status == "pass"
        assert set(result.subchecks[0].detail.split(", ")) == {
            "mx1.example.com",
            "mx2.example.com",
        }

    def test_run__counts_the_exchanges_it_hides(self, lookup, dns_resolver):
        dns_resolver.add(
            "example.com",
            "MX",
            *(f"{index} mx{index}.example.com." for index in range(1, 8)),
        )

        result = MxCheck.run("example.com", lookup)

        assert result.subchecks[0].detail.endswith(" (+2 more)")


class TestSpfQualifier:
    @pytest.mark.parametrize(
        ("record", "qualifier"),
        [
            ("v=spf1 -all", "-"),
            ("v=spf1 ~all", "~"),
            ("v=spf1 ?all", "?"),
            ("v=spf1 +all", "+"),
            ("v=spf1 all", "+"),
            ("v=spf1 -mx", ""),
        ],
    )
    def test_qualifier__reads_the_all_mechanism(self, record, qualifier):
        assert SpfCheck.qualifier(record) == qualifier


class TestSpfResolve:
    def test_resolve__reports_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "TXT", dns.exception.DNSException())

        assert SpfCheck.resolve("example.com", lookup).error

    def test_resolve__returns_no_records_without_spf(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"hello"')

        assert SpfCheck.resolve("example.com", lookup).records == ()

    def test_resolve__returns_every_spf_record(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"', '"v=spf1 ~all"')

        assert set(SpfCheck.resolve("example.com", lookup).records) == {
            "v=spf1 -all",
            "v=spf1 ~all",
        }

    def test_resolve__walks_an_include(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 include:_spf.example.com -all"')
        dns_resolver.add(
            "_spf.example.com", "TXT", '"v=spf1 ip4:8.8.8.8 ip4:192.0.2.1 -all"'
        )

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.lookups == 1
        assert spf.addresses == ("8.8.8.8",)
        assert spf.exact == ("8.8.8.8",)

    def test_resolve__walks_an_include_only_once(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 include:example.com -all"')

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.lookups == 1
        assert spf.addresses == ()

    def test_resolve__skips_an_include_with_several_records(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 include:_spf.example.com -all"')
        dns_resolver.add("_spf.example.com", "TXT", '"v=spf1 -all"', '"v=spf1 ~all"')

        assert SpfCheck.resolve("example.com", lookup).addresses == ()

    def test_resolve__skips_an_include_without_an_spf_record(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("example.com", "TXT", '"v=spf1 include:_spf.example.com -all"')
        dns_resolver.add("_spf.example.com", "TXT", '"hello"')

        assert SpfCheck.resolve("example.com", lookup).addresses == ()

    def test_resolve__skips_a_failed_include_lookup(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 include:_spf.example.com -all"')
        dns_resolver.fail("_spf.example.com", "TXT", dns.exception.DNSException())

        assert SpfCheck.resolve("example.com", lookup).addresses == ()

    def test_resolve__walks_an_a_mechanism(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 a -all"')
        dns_resolver.add("example.com", "A", "8.8.8.8")

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.addresses == ("8.8.8.8",)
        assert spf.exact == ("8.8.8.8",)

    def test_resolve__walks_an_a_mechanism_with_a_host(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 a:mail.example.com -all"')
        dns_resolver.add("mail.example.com", "A", "8.8.8.8")

        assert SpfCheck.resolve("example.com", lookup).addresses == ("8.8.8.8",)

    def test_resolve__walks_an_mx_mechanism(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 mx -all"')
        dns_resolver.add("example.com", "MX", "10 mx.example.com.")
        dns_resolver.add("mx.example.com", "A", "8.8.8.8")

        assert SpfCheck.resolve("example.com", lookup).addresses == ("8.8.8.8",)

    def test_resolve__samples_an_a_mechanism_network(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 a:example.com/24 -all"')
        dns_resolver.add("example.com", "A", "8.8.8.0")

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.addresses == ("8.8.8.1",)
        assert spf.sampled == 1

    def test_resolve__samples_a_dual_stack_network(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 a:example.com/24//64 -all"')
        dns_resolver.add("example.com", "A", "8.8.8.0")
        dns_resolver.add("example.com", "AAAA", "2001:4860::")

        spf = SpfCheck.resolve("example.com", lookup)

        assert "8.8.8.1" in spf.addresses
        assert "2001:4860::1" in spf.addresses
        assert spf.sampled == 2

    def test_resolve__keeps_a_single_ip4_exact(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.addresses == ("8.8.8.8",)
        assert spf.exact == ("8.8.8.8",)
        assert spf.sampled == 0

    def test_resolve__samples_an_ip4_network(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.0/24 -all"')

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.addresses == ("8.8.8.1",)
        assert spf.exact == ()
        assert spf.sampled == 1

    def test_resolve__keeps_a_single_ip6_exact(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip6:2001:4860::1 -all"')

        assert SpfCheck.resolve("example.com", lookup).exact == ("2001:4860::1",)

    def test_resolve__samples_an_ip6_network(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip6:2001:4860::/32 -all"')

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.addresses == ("2001:4860::1",)
        assert spf.sampled == 1

    def test_resolve__keeps_a_single_host_network_exact(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8/32 -all"')

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.addresses == ("8.8.8.8",)
        assert spf.exact == ("8.8.8.8",)
        assert spf.sampled == 0

    def test_resolve__ignores_an_invalid_network(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:999.1.1.1/24 -all"')

        assert SpfCheck.resolve("example.com", lookup).addresses == ()

    @pytest.mark.parametrize(
        "record", ['"v=spf1 a:%{d} -all"', '"v=spf1 ip4:%{d} -all"']
    )
    def test_resolve__skips_a_macro_mechanism(self, lookup, dns_resolver, record):
        dns_resolver.add("example.com", "TXT", record)

        assert SpfCheck.resolve("example.com", lookup).addresses == ()

    def test_resolve__exhausts_the_lookup_budget(self, lookup, dns_resolver):
        terms = " ".join("exists:a" for _ in range(11))
        dns_resolver.add("example.com", "TXT", f'"v=spf1 {terms} -all"')

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.exhausted is True
        assert spf.lookups == 11

    def test_resolve__counts_every_lookup_term(self, lookup, dns_resolver):
        dns_resolver.add(
            "example.com",
            "TXT",
            '"v=spf1 include:a.example.com a mx ptr exists:b.example.com '
            'redirect=c.example.com -all"',
        )

        spf = SpfCheck.resolve("example.com", lookup)

        assert spf.lookups == 6


class TestSpfReverseDns:
    def test_reverse_dns__skips_without_an_address(self, lookup):
        assert SpfCheck.reverse_dns(SpfLookup(), lookup) == SubCheck(
            "Reverse DNS", "skip", "No SPF address", severity="weak"
        )

    def test_reverse_dns__skips_a_range_only_record(self, lookup):
        spf = SpfLookup(addresses=("8.8.8.1",))

        assert SpfCheck.reverse_dns(spf, lookup) == SubCheck(
            "Reverse DNS", "skip", "SPF covers ranges only", severity="weak"
        )

    def test_reverse_dns__skips_without_any_answer(self, lookup, dns_resolver):
        dns_resolver.fail("8.8.8.8.in-addr.arpa", "PTR", dns.exception.DNSException())
        spf = SpfLookup(addresses=("8.8.8.8",), exact=("8.8.8.8",))

        assert SpfCheck.reverse_dns(spf, lookup).detail == "No reverse DNS answer"

    def test_reverse_dns__passes_when_every_name_resolves_back(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("8.8.8.8.in-addr.arpa", "PTR", "dns.google.")
        dns_resolver.add("dns.google", "A", "8.8.8.8")
        spf = SpfLookup(addresses=("8.8.8.8",), exact=("8.8.8.8",))

        result = SpfCheck.reverse_dns(spf, lookup)

        assert result.status == "pass"
        assert (
            result.detail == "1 of 1 addresses point at a hostname that resolves back"
        )

    def test_reverse_dns__lists_the_mismatched_addresses(self, lookup, dns_resolver):
        dns_resolver.add("8.8.8.8.in-addr.arpa", "PTR", "host.example.com.")
        dns_resolver.add("host.example.com", "A", "8.8.4.4")
        spf = SpfLookup(addresses=("8.8.8.8",), exact=("8.8.8.8",))

        result = SpfCheck.reverse_dns(spf, lookup)

        assert result.status == "fail"
        assert result.severity == "weak"
        assert result.addresses == ("8.8.8.8",)

    def test_has_matching_reverse_dns__returns_none_without_an_answer(
        self, lookup, dns_resolver
    ):
        dns_resolver.fail("8.8.8.8.in-addr.arpa", "PTR", dns.exception.DNSException())

        assert SpfCheck.has_matching_reverse_dns("8.8.8.8", lookup) is None

    def test_has_matching_reverse_dns__returns_false_for_a_forward_mismatch(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("8.8.8.8.in-addr.arpa", "PTR", "host.example.com.")
        dns_resolver.add("host.example.com", "A", "8.8.4.4")

        assert SpfCheck.has_matching_reverse_dns("8.8.8.8", lookup) is False

    def test_has_matching_reverse_dns__returns_true_for_a_match(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("8.8.8.8.in-addr.arpa", "PTR", "dns.google.")
        dns_resolver.add("dns.google", "A", "8.8.8.8")

        assert SpfCheck.has_matching_reverse_dns("8.8.8.8", lookup) is True


class TestSpfRun:
    def test_run__skips_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "TXT", dns.exception.DNSException())

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks == (SubCheck("SPF record", "skip", "Lookup failed"),)
        assert result.detail == "Lookup failed."

    def test_run__fails_without_a_record(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"hello"')

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("SPF record", "fail", "No SPF record", severity="blocking"),
        )
        assert result.detail == "No SPF record."

    def test_run__fails_on_several_records(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"', '"v=spf1 ~all"')

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck(
                "SPF record", "fail", "2 SPF records (permerror).", severity="blocking"
            ),
        )
        assert result.detail == "2 SPF records (permerror)."

    def test_run__grades_the_record(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 ~all"')

        result = SpfCheck.run("example.com", lookup)

        labels = [subcheck.label for subcheck in result.subchecks]
        assert labels == [
            "SPF record",
            "Lookup limit",
            "Strict all",
            "Reverse DNS",
            "SPF TTL",
        ]
        assert result.subchecks[0] == SubCheck("SPF record", "pass", "1 record")
        assert result.subchecks[1].detail == "0 DNS lookups (limit 10)"
        assert result.subchecks[2] == SubCheck(
            "Strict all", "fail", "~all", severity="weak"
        )

    def test_run__spells_out_a_single_lookup(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 include:_spf.example.com -all"')
        dns_resolver.add("_spf.example.com", "TXT", '"v=spf1 -all"')

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks[1].detail == "1 DNS lookup (limit 10)"

    def test_run__reports_an_exhausted_budget_as_blocking(self, lookup, dns_resolver):
        terms = " ".join("exists:a" for _ in range(11))
        dns_resolver.add("example.com", "TXT", f'"v=spf1 {terms} -all"')

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks[1].status == "fail"
        assert result.subchecks[1].severity == "blocking"

    def test_run__passes_a_strict_all(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"')

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks[2] == SubCheck(
            "Strict all", "pass", "-all", severity="weak"
        )

    def test_run__reports_a_missing_all_mechanism(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -mx"')

        result = SpfCheck.run("example.com", lookup)

        assert result.subchecks[2] == SubCheck(
            "Strict all", "fail", "No all mechanism", severity="weak"
        )


class TestDmarcCheck:
    def test_run__skips_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("_dmarc.example.com", "TXT", dns.exception.DNSException())

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks == (SubCheck("DMARC record", "skip", "Lookup failed"),)
        assert result.detail == "DMARC lookup failed."

    def test_run__fails_without_a_record(self, lookup):
        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("DMARC record", "fail", "No DMARC record", severity="blocking"),
        )
        assert result.detail == "No DMARC record."

    def test_run__fails_on_several_records(self, lookup, dns_resolver):
        dns_resolver.add(
            "_dmarc.example.com", "TXT", '"v=DMARC1; p=reject"', '"v=DMARC1; p=none"'
        )

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck(
                "DMARC record",
                "fail",
                "2 DMARC records (permerror).",
                severity="blocking",
            ),
        )
        assert result.detail == "2 DMARC records (permerror)."

    def test_run__fails_an_invalid_policy(self, lookup, dns_resolver):
        dns_resolver.add("_dmarc.example.com", "TXT", '"v=DMARC1; p=foo"')

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("DMARC record", "pass", "1 record"),
            SubCheck("Policy", "fail", "No valid p tag", severity="blocking"),
            SubCheck("DMARC TTL", "pass", "30 minutes"),
        )

    def test_run__passes_a_strict_policy(self, lookup, dns_resolver):
        dns_resolver.add(
            "_dmarc.example.com",
            "TXT",
            '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"',
        )

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks[:4] == (
            SubCheck("DMARC record", "pass", "1 record"),
            SubCheck("Policy", "pass", "p=reject", severity="weak"),
            SubCheck(
                "Aggregate reports",
                "pass",
                "mailto:dmarc@example.com",
                severity="weak",
            ),
            SubCheck("Full coverage", "pass", "pct=100", severity="weak"),
        )
        assert result.subchecks[4].label == "DMARC TTL"

    @pytest.mark.parametrize("policy", ["none", "quarantine"])
    def test_run__fails_a_loose_policy(self, lookup, dns_resolver, policy):
        dns_resolver.add("_dmarc.example.com", "TXT", f'"v=DMARC1; p={policy}"')

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks[1] == SubCheck(
            "Policy", "fail", f"p={policy}", severity="weak"
        )

    def test_run__fails_without_reports(self, lookup, dns_resolver):
        dns_resolver.add("_dmarc.example.com", "TXT", '"v=DMARC1; p=reject"')

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks[2] == SubCheck(
            "Aggregate reports", "fail", "No rua", severity="weak"
        )

    def test_run__fails_a_partial_policy(self, lookup, dns_resolver):
        dns_resolver.add("_dmarc.example.com", "TXT", '"v=DMARC1; p=reject; pct=50"')

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks[3] == SubCheck(
            "Full coverage", "fail", "pct=50", severity="weak"
        )

    def test_run__keeps_the_default_coverage_for_an_invalid_pct(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("_dmarc.example.com", "TXT", '"v=DMARC1; p=reject; pct=abc"')

        result = DmarcCheck.run("example.com", lookup)

        assert result.subchecks[3].status == "pass"


class TestMtaStsParseTarget:
    def test_parse_target__accepts_https(self):
        parsed, port = MtaStsCheck.parse_target(
            "https://mta-sts.example.com/.well-known/mta-sts.txt"
        )

        assert parsed.hostname == "mta-sts.example.com"
        assert port is None

    def test_parse_target__keeps_the_port(self):
        _, port = MtaStsCheck.parse_target("https://mta-sts.example.com:8443/policy")

        assert port == 8443

    @pytest.mark.parametrize(
        "url",
        [
            "http://mta-sts.example.com/policy",
            "https:///policy",
            "https://mta-sts.example.com:notaport/policy",
        ],
    )
    def test_parse_target__rejects_a_bad_url(self, url):
        assert MtaStsCheck.parse_target(url) is None


class TestMtaStsFetchNetloc:
    def test_fetch_netloc__returns_none_without_an_address(self, lookup):
        assert MtaStsCheck.fetch_netloc("mta-sts.example.com", None, lookup) is None

    def test_fetch_netloc__returns_none_for_a_private_address(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("mta-sts.example.com", "A", "192.168.0.1")

        assert MtaStsCheck.fetch_netloc("mta-sts.example.com", None, lookup) is None

    def test_fetch_netloc__returns_none_when_one_address_is_private(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8", "192.168.0.1")

        assert MtaStsCheck.fetch_netloc("mta-sts.example.com", None, lookup) is None

    def test_fetch_netloc__returns_the_address(self, lookup, dns_resolver):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")

        assert (
            MtaStsCheck.fetch_netloc("mta-sts.example.com", None, lookup) == "8.8.8.8"
        )

    def test_fetch_netloc__appends_the_port(self, lookup, dns_resolver):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")

        assert (
            MtaStsCheck.fetch_netloc("mta-sts.example.com", 8443, lookup)
            == "8.8.8.8:8443"
        )

    def test_fetch_netloc__brackets_an_ipv6_address(self, lookup, dns_resolver):
        dns_resolver.add("mta-sts.example.com", "AAAA", "2001:4860:4860::8888")

        assert (
            MtaStsCheck.fetch_netloc("mta-sts.example.com", None, lookup)
            == "[2001:4860:4860::8888]"
        )


class TestMtaStsStreamBody:
    URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"

    def test_stream_body__returns_the_body(self, http):
        http(lambda request: httpx.Response(200, content=b"policy"))
        parsed, port = MtaStsCheck.parse_target(self.URL)

        body = MtaStsCheck.stream_body(parsed, "8.8.8.8", port, 64)

        assert body == b"policy"

    def test_stream_body__sends_the_original_host_header(self, http):
        seen = {}

        def handler(request):
            seen["host"] = request.headers["host"]
            return httpx.Response(200, content=b"policy")

        http(handler)
        parsed, port = MtaStsCheck.parse_target(
            "https://mta-sts.example.com:8443/.well-known/mta-sts.txt"
        )

        MtaStsCheck.stream_body(parsed, "8.8.8.8", port, 64)

        assert seen["host"] == "mta-sts.example.com:8443"

    def test_stream_body__rejects_a_non_200_response(self, http):
        http(lambda request: httpx.Response(404))
        parsed, port = MtaStsCheck.parse_target(self.URL)

        assert MtaStsCheck.stream_body(parsed, "8.8.8.8", port, 64) is None

    def test_stream_body__stops_at_the_size_limit(self, http):
        http(lambda request: httpx.Response(200, content=b"too large"))
        parsed, port = MtaStsCheck.parse_target(self.URL)

        assert MtaStsCheck.stream_body(parsed, "8.8.8.8", port, 4) is None

    def test_stream_body__stops_at_the_deadline(self, http, monkeypatch):
        http(lambda request: httpx.Response(200, content=b"policy"))
        parsed, port = MtaStsCheck.parse_target(self.URL)
        ticks = iter([0, 100])
        monkeypatch.setattr(
            "domains.check.evaluation.time.monotonic", lambda: next(ticks)
        )

        assert MtaStsCheck.stream_body(parsed, "8.8.8.8", port, 64) is None


class TestMtaStsParsePolicy:
    def test_parse_policy__returns_the_policy(self):
        body = (
            b"version: STSv1\n"
            b"mode: enforce\n"
            b"max_age: 86400\n"
            b"mx: mx1.example.com\n"
            b"mx: *.example.com\n"
        )

        assert MtaStsCheck.parse_policy(body) == {
            "mode": "enforce",
            "mx": ("mx1.example.com", "*.example.com"),
        }

    def test_parse_policy__accepts_whitespace_and_case(self):
        body = (
            b"garbage line\r\n"
            b"unknown: value\r\n"
            b"Version : STSv1\r\n"
            b"Mode: Testing\r\n"
            b"Max_Age : 1\r\n"
            b"MX : mx.example.com\r\n"
        )

        assert MtaStsCheck.parse_policy(body) == {
            "mode": "testing",
            "mx": ("mx.example.com",),
        }

    @pytest.mark.parametrize(
        "body",
        [
            b"\xff",
            b"version: STSv1\nmode: enforce\nmx: mx.example.com\n",
            b"version: STSv1\nmode: enforce\nmax_age: 0\nmx: mx.example.com\n",
            b"version: STSv1\nmode: enforce\nmax_age: 10\n",
            b"version: STSv1\nmode: other\nmax_age: 10\nmx: mx.example.com\n",
            b"version: OTHER\nmode: enforce\nmax_age: 10\nmx: mx.example.com\n",
        ],
    )
    def test_parse_policy__rejects_a_malformed_document(self, body):
        assert MtaStsCheck.parse_policy(body) is None


class TestMtaStsFetchBody:
    URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"

    def test_fetch_body__serves_the_cached_body(self, lookup):
        cache.set(
            f"domain_check:fetch:{__import__('hashlib').sha256(self.URL.encode()).hexdigest()}",
            b"cached",
        )

        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) == b"cached"

    def test_fetch_body__rejects_a_non_https_url(self, lookup):
        assert MtaStsCheck.fetch_body("http://example.com", 64, lookup) is None

    def test_fetch_body__rejects_a_host_without_a_global_address(self, lookup):
        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) is None

    def test_fetch_body__returns_and_caches_the_body(self, lookup, dns_resolver, http):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        http(lambda request: httpx.Response(200, content=b"policy"))

        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) == b"policy"
        assert (
            cache.get(
                f"domain_check:fetch:{__import__('hashlib').sha256(self.URL.encode()).hexdigest()}"
            )
            == b"policy"
        )

    def test_fetch_body__returns_none_for_a_non_200_response(
        self, lookup, dns_resolver, http
    ):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        http(lambda request: httpx.Response(404))

        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) is None

    def test_fetch_body__retries_a_transport_error(
        self, lookup, dns_resolver, http, monkeypatch
    ):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        attempts = []

        def handler(request):
            attempts.append(request)
            if len(attempts) == 1:
                raise httpx.ConnectError(CONNECTION_REFUSED)
            return httpx.Response(200, content=b"policy")

        http(handler)
        monkeypatch.setattr("domains.check.evaluation.time.sleep", lambda seconds: None)

        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) == b"policy"

    def test_fetch_body__gives_up_after_the_last_transport_error(
        self, lookup, dns_resolver, http, monkeypatch
    ):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")

        def handler(request):
            raise httpx.ConnectError(CONNECTION_REFUSED)

        http(handler)
        monkeypatch.setattr("domains.check.evaluation.time.sleep", lambda seconds: None)

        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) is None

    def test_fetch_body__returns_none_for_an_invalid_url(
        self, lookup, dns_resolver, http
    ):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")

        def handler(request):
            raise httpx.InvalidURL(INVALID_URL)

        http(handler)

        assert MtaStsCheck.fetch_body(self.URL, 64, lookup) is None


class TestMtaStsFetchPolicy:
    def test_fetch_policy__returns_the_parsed_policy(self, lookup, dns_resolver, http):
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        http(
            lambda request: httpx.Response(
                200,
                content=b"version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx.example.com\n",
            )
        )

        assert MtaStsCheck.fetch_policy("example.com", lookup) == {
            "mode": "enforce",
            "mx": ("mx.example.com",),
        }

    def test_fetch_policy__returns_none_without_a_body(self, lookup):
        assert MtaStsCheck.fetch_policy("example.com", lookup) is None


class TestMtaStsRun:
    def test_run__skips_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("_mta-sts.example.com", "TXT", dns.exception.DNSException())

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("MTA-STS record", "skip", "Lookup failed"),
        )
        assert result.detail == "MTA-STS lookup failed."

    def test_run__fails_without_a_valid_record(self, lookup, dns_resolver):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"hello"')

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("MTA-STS record", "fail", "No valid MTA-STS record"),
        )
        assert result.detail == "No valid MTA-STS record."

    def test_run__skips_the_policy_that_does_not_fetch(self, lookup, dns_resolver):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"v=STSv1; id=1"')

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[0] == SubCheck("MTA-STS record", "pass", "id=1")
        assert result.subchecks[1] == SubCheck("Policy", "fail", "No fetchable policy")
        assert result.subchecks[2].label == "MTA-STS TTL"

    def test_run__skips_the_mx_match_on_a_failed_lookup(
        self, lookup, dns_resolver, http
    ):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"v=STSv1; id=1"')
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        dns_resolver.fail("example.com", "MX", dns.exception.DNSException())
        http(
            lambda request: httpx.Response(
                200,
                content=b"version: STSv1\nmode: testing\nmax_age: 86400\nmx: mx.example.com\n",
            )
        )

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[2] == SubCheck(
            "Enforced mode", "fail", "testing", severity="weak"
        )
        assert result.subchecks[3] == SubCheck("MX match", "skip", "MX lookup failed")

    def test_run__passes_a_matching_policy(self, lookup, dns_resolver, http):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"v=STSv1; id=1"')
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        dns_resolver.add("example.com", "MX", "10 mx1.example.com.")
        http(
            lambda request: httpx.Response(
                200,
                content=b"version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\n",
            )
        )

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[2] == SubCheck(
            "Enforced mode", "pass", "enforce", severity="weak"
        )
        assert result.subchecks[3] == SubCheck("MX match", "pass", "All MX hosts match")

    def test_run__accepts_a_wildcard_pattern(self, lookup, dns_resolver, http):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"v=STSv1; id=1"')
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        dns_resolver.add("example.com", "MX", "10 mx1.example.com.")
        http(
            lambda request: httpx.Response(
                200,
                content=b"version: STSv1\nmode: enforce\nmax_age: 86400\nmx: *.example.com\n",
            )
        )

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[3].status == "pass"

    def test_run__fails_a_mismatched_policy(self, lookup, dns_resolver, http):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"v=STSv1; id=1"')
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        dns_resolver.add("example.com", "MX", "10 mx2.example.com.")
        http(
            lambda request: httpx.Response(
                200,
                content=b"version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\n",
            )
        )

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[3] == SubCheck(
            "MX match", "fail", "MX does not match the policy"
        )

    def test_run__fails_without_mx_exchanges(self, lookup, dns_resolver, http):
        dns_resolver.add("_mta-sts.example.com", "TXT", '"v=STSv1; id=1"')
        dns_resolver.add("mta-sts.example.com", "A", "8.8.8.8")
        http(
            lambda request: httpx.Response(
                200,
                content=b"version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\n",
            )
        )

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[3].status == "fail"

    def test_run__skips_an_invalid_record_before_a_valid_one(
        self, lookup, dns_resolver
    ):
        dns_resolver.add(
            "_mta-sts.example.com", "TXT", '"v=STSv1; id=bad-id"', '"v=STSv1; id=good"'
        )

        result = MtaStsCheck.run("example.com", lookup)

        assert result.subchecks[0] == SubCheck("MTA-STS record", "pass", "id=good")


class TestTlsRptCheck:
    def test_reporting_address__returns_the_rua(self):
        assert (
            TlsRptCheck.reporting_address("v=TLSRPTv1; rua=mailto:reports@example.com")
            == "mailto:reports@example.com"
        )

    def test_reporting_address__returns_an_empty_string_without_rua(self):
        assert TlsRptCheck.reporting_address("v=TLSRPTv1") == ""

    def test_reporting_address__keeps_the_last_rua(self):
        assert (
            TlsRptCheck.reporting_address(
                "v=TLSRPTv1; RUA = mailto:one@example.com ; rua=mailto:two@example.com"
            )
            == "mailto:two@example.com"
        )

    def test_run__skips_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("_smtp._tls.example.com", "TXT", dns.exception.DNSException())

        result = TlsRptCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("TLS-RPT record", "skip", "Lookup failed"),
        )
        assert result.detail == "TLS-RPT lookup failed."

    def test_run__fails_without_a_record(self, lookup):
        result = TlsRptCheck.run("example.com", lookup)

        assert result.subchecks == (
            SubCheck("TLS-RPT record", "fail", "No TLS-RPT record"),
        )
        assert result.detail == "No TLS-RPT record."

    def test_run__passes_a_record_with_rua(self, lookup, dns_resolver):
        dns_resolver.add(
            "_smtp._tls.example.com",
            "TXT",
            '"v=TLSRPTv1; rua=mailto:reports@example.com"',
        )

        result = TlsRptCheck.run("example.com", lookup)

        assert result.subchecks[:2] == (
            SubCheck("TLS-RPT record", "pass", "1 record"),
            SubCheck(
                "Reporting address",
                "pass",
                "mailto:reports@example.com",
            ),
        )
        assert result.subchecks[2].label == "TLS-RPT TTL"
        assert result.detail == "Record with rua."

    def test_run__fails_a_record_without_rua(self, lookup, dns_resolver):
        dns_resolver.add("_smtp._tls.example.com", "TXT", '"v=TLSRPTv1"')

        result = TlsRptCheck.run("example.com", lookup)

        assert result.subchecks[1] == SubCheck("Reporting address", "fail", "No rua")
        assert result.detail == "Record without rua."


SPF_ADDRESS = "8.8.8.8"


def refuse_all_address_providers(dns_resolver, address=SPF_ADDRESS):
    for provider in PUBLIC_ADDRESS_PROVIDERS:
        dns_resolver.add(
            f"{reverse_pointer(address)}.{provider.zone}", "A", "127.255.255.1"
        )


class TestBlocklistAnswer:
    def test_problem__reports_a_refusal(self):
        assert BlocklistAnswer(refused=True).problem == "refused the query"

    def test_problem__reports_a_failure(self):
        assert BlocklistAnswer(failed=True).problem == "did not answer"

    def test_problem__is_empty_without_a_problem(self):
        assert BlocklistAnswer().problem == ""


class TestBlocklistsZone:
    def test_zone__uses_the_keyed_zone(self, settings):
        settings.SPAMHAUS_KEY = "abc"
        provider = BlocklistProvider(
            "Spamhaus DBL", "dbl.spamhaus.org", keyed_zone="{key}.dbl.dq.spamhaus.net"
        )

        assert BlocklistsCheck.zone(provider) == "abc.dbl.dq.spamhaus.net"

    def test_zone__keeps_the_plain_zone_without_a_key(self, settings):
        settings.SPAMHAUS_KEY = ""
        provider = BlocklistProvider(
            "Spamhaus DBL", "dbl.spamhaus.org", keyed_zone="{key}.dbl.dq.spamhaus.net"
        )

        assert BlocklistsCheck.zone(provider) == "dbl.spamhaus.org"

    def test_zone__keeps_the_plain_zone_without_a_keyed_zone(self, settings):
        settings.SPAMHAUS_KEY = "abc"

        assert (
            BlocklistsCheck.zone(BlocklistProvider("SpamCop", "bl.spamcop.net"))
            == "bl.spamcop.net"
        )


class TestResolveCodes:
    def test_resolve_codes__returns_codes(self, lookup, dns_resolver):
        dns_resolver.add("query.example.com", "A", "127.0.0.2")

        assert BlocklistsCheck.resolve_codes("query.example.com", lookup) == (
            BlocklistAnswer(codes=("127.0.0.2",))
        )

    def test_resolve_codes__reports_a_refusal(self, lookup, dns_resolver):
        dns_resolver.add("query.example.com", "A", "127.255.255.1")

        answer = BlocklistsCheck.resolve_codes("query.example.com", lookup)

        assert answer.refused is True
        assert ipaddress.ip_address("127.255.255.1") in REFUSAL_NETWORK

    def test_resolve_codes__reports_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("query.example.com", "A", dns.exception.DNSException())

        assert BlocklistsCheck.resolve_codes("query.example.com", lookup) == (
            BlocklistAnswer(failed=True)
        )

    def test_resolve_codes__reports_an_unlisted_query(self, lookup):
        assert BlocklistsCheck.resolve_codes("query.example.com", lookup) == (
            BlocklistAnswer()
        )


class TestDomainListing:
    def test_domain_listing__lists_the_domain(self, lookup, dns_resolver):
        dns_resolver.add("example.com.dbl.spamhaus.org", "A", "127.0.0.2")

        assert BlocklistsCheck.domain_listing("example.com", lookup) == (
            ["Spamhaus DBL (127.0.0.2)"],
            [],
        )

    def test_domain_listing__reports_a_refusal(self, lookup, dns_resolver):
        dns_resolver.add("example.com.dbl.spamhaus.org", "A", "127.255.255.1")

        assert BlocklistsCheck.domain_listing("example.com", lookup) == (
            [],
            ["Spamhaus DBL refused the query"],
        )

    def test_domain_listing__reports_a_failure(self, lookup, dns_resolver):
        dns_resolver.fail(
            "example.com.dbl.spamhaus.org", "A", dns.exception.DNSException()
        )

        assert BlocklistsCheck.domain_listing("example.com", lookup) == (
            [],
            ["Spamhaus DBL did not answer"],
        )


class TestAddressListing:
    def test_address_listing__lists_the_address(self, lookup, dns_resolver):
        dns_resolver.add("8.8.8.8.zen.spamhaus.org", "A", "127.0.0.5")

        listed, problems = BlocklistsCheck.address_listing(SPF_ADDRESS, lookup)

        assert "Spamhaus ZEN (8.8.8.8)" in listed
        assert problems == []

    def test_address_listing__reports_a_refusal(self, lookup, dns_resolver):
        dns_resolver.add("8.8.8.8.zen.spamhaus.org", "A", "127.255.255.1")

        listed, problems = BlocklistsCheck.address_listing(SPF_ADDRESS, lookup)

        assert listed == []
        assert "Spamhaus ZEN refused the query" in problems

    def test_address_listing__reports_a_failure(self, lookup, dns_resolver):
        dns_resolver.fail("8.8.8.8.zen.spamhaus.org", "A", dns.exception.DNSException())
        dns_resolver.fail("8.8.8.8.bl.spamcop.net", "A", dns.exception.DNSException())

        listed, problems = BlocklistsCheck.address_listing(SPF_ADDRESS, lookup)

        assert listed == []
        assert "Spamhaus ZEN did not answer" in problems
        assert "SpamCop did not answer" in problems


class TestBlocklistsRun:
    def test_run__lists_the_domain(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')
        dns_resolver.add("example.com.dbl.spamhaus.org", "A", "127.0.0.2")

        result = BlocklistsCheck.run("example.com", lookup)

        assert result.subchecks[0] == SubCheck(
            "Domain blocklists",
            "fail",
            "Listed on Spamhaus DBL (127.0.0.2)",
            severity="blocking",
        )
        assert result.subchecks[1].status == "pass"
        assert "Domain listed on spamhaus dbl (127.0.0.2)" in result.detail
        assert result.status == "fail"

    def test_run__skips_a_domain_without_a_blocklist(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')
        dns_resolver.fail(
            "example.com.dbl.spamhaus.org", "A", dns.exception.DNSException()
        )

        result = BlocklistsCheck.run("example.com", lookup)

        assert result.subchecks[0] == SubCheck(
            "Domain blocklists", "skip", "Spamhaus DBL did not answer"
        )
        assert "Domain blocklist lookup unavailable" in result.detail
        assert result.status == "pass"

    def test_run__skips_when_every_address_query_is_refused(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')
        refuse_all_address_providers(dns_resolver)

        result = BlocklistsCheck.run("example.com", lookup)

        assert result.subchecks[1].status == "skip"
        assert "SPF address blocklist lookup unavailable" in result.detail
        assert "unavailable:" in result.detail

    def test_run__passes_with_a_single_refused_provider(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')
        dns_resolver.add("8.8.8.8.zen.spamhaus.org", "A", "127.255.255.1")

        result = BlocklistsCheck.run("example.com", lookup)

        assert result.subchecks[1] == SubCheck(
            "SPF address blocklists",
            "pass",
            "1 address not listed (Spamhaus ZEN refused the query)",
        )

    def test_run__lists_an_address(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')
        dns_resolver.add("8.8.8.8.zen.spamhaus.org", "A", "127.0.0.2")

        result = BlocklistsCheck.run("example.com", lookup)

        assert result.subchecks[1] == SubCheck(
            "SPF address blocklists",
            "fail",
            "Listed on Spamhaus ZEN (8.8.8.8)",
            severity="blocking",
        )
        assert "SPF address listed on spamhaus zen (8.8.8.8)" in result.detail

    def test_run__skips_without_an_spf_address(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"')

        result = BlocklistsCheck.run("example.com", lookup)

        assert result.subchecks[1] == SubCheck(
            "SPF address blocklists", "skip", "No SPF address"
        )
        assert "SPF address not checked" in result.detail

    def test_run__reports_sampled_ranges(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.0/24 -all"')

        result = BlocklistsCheck.run("example.com", lookup)

        assert "sampled 1 network ranges" in result.detail

    def test_run__combines_the_unavailable_providers(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 ip4:8.8.8.8 -all"')
        dns_resolver.fail(
            "example.com.dbl.spamhaus.org", "A", dns.exception.DNSException()
        )
        dns_resolver.add("8.8.8.8.zen.spamhaus.org", "A", "127.255.255.1")

        result = BlocklistsCheck.run("example.com", lookup)

        assert (
            "unavailable: Spamhaus DBL did not answer, Spamhaus ZEN refused the query"
            in result.detail
        )
