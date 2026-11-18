import datetime as dt
from types import SimpleNamespace

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from conftest import StubResolver
from domains.check.lookup import Answer, AsnRecord, Lookup, MxLookup, MxRecord


def record(text, record_type):
    return dns.rdata.from_text(dns.rdataclass.IN, record_type, text)


class FlakyResolver(StubResolver):
    def __init__(self, failures=1, error=dns.exception.Timeout):
        super().__init__()
        self.failures = failures
        self.error = error
        self.calls = 0

    def resolve(self, *args, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error()
        return super().resolve(*args, **kwargs)


class Authority:
    def __init__(self, ttl):
        self.rrset = SimpleNamespace(ttl=ttl)
        self.lifetime = 0
        self.nameservers = []
        self.queries = []

    def resolve(self, name, record_type, lifetime=None):
        self.queries.append(str(name).rstrip("."))
        return self


@pytest.fixture
def lookup(dns_resolver):
    return Lookup()


class TestRenderRecord:
    def test_render_record__joins_txt_strings(self):
        assert (
            Lookup.render_record(
                record('"hello" "world"', dns.rdatatype.TXT), dns.rdatatype.TXT
            )
            == "helloworld"
        )

    def test_render_record__prefixes_an_mx_with_its_preference(self):
        assert (
            Lookup.render_record(
                record("10 mx.example.com.", dns.rdatatype.MX), dns.rdatatype.MX
            )
            == "10 mx.example.com"
        )

    def test_render_record__returns_a_plain_address(self):
        assert (
            Lookup.render_record(record("192.0.2.1", dns.rdatatype.A), dns.rdatatype.A)
            == "192.0.2.1"
        )

    def test_render_record__returns_an_ipv6_address(self):
        assert (
            Lookup.render_record(
                record("2001:db8::1", dns.rdatatype.AAAA), dns.rdatatype.AAAA
            )
            == "2001:db8::1"
        )

    def test_render_record__falls_back_to_the_text_form(self):
        assert (
            Lookup.render_record(
                record("target.example.com.", dns.rdatatype.CNAME), dns.rdatatype.CNAME
            )
            == "target.example.com."
        )


class TestQuery:
    def test_query__returns_the_records(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"')

        assert lookup.query("example.com", dns.rdatatype.TXT) == Answer(
            ("v=spf1 -all",),
            ttl=dt.timedelta(minutes=30),
            canonical_name="example.com",
        )

    def test_query__memoizes_by_normalized_name(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"')

        lookup.query("EXAMPLE.com.", dns.rdatatype.TXT)
        lookup.query("example.com", dns.rdatatype.TXT)

        assert dns_resolver.lookups.count(("example.com", "TXT")) == 1

    @pytest.mark.parametrize(
        "error",
        [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer],
    )
    def test_query__treats_a_missing_record_as_an_empty_answer(self, lookup, error):
        lookup._resolver.fail("example.com", "TXT", error())

        assert lookup.query("example.com", dns.rdatatype.TXT) == Answer()

    def test_query__retries_a_transient_error(self, monkeypatch):
        resolver = FlakyResolver()
        resolver.add("example.com", "TXT", '"v=spf1 -all"')
        monkeypatch.setattr(dns.resolver, "Resolver", lambda *args, **kwargs: resolver)
        monkeypatch.setattr("domains.check.lookup.time.sleep", lambda seconds: None)

        assert Lookup().query("example.com", dns.rdatatype.TXT).records == (
            "v=spf1 -all",
        )
        assert resolver.calls == 2

    @pytest.mark.parametrize(
        "error",
        [
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ],
    )
    def test_query__fails_after_the_last_transient_error(self, monkeypatch, error):
        resolver = FlakyResolver(failures=3, error=error)
        monkeypatch.setattr(dns.resolver, "Resolver", lambda *args, **kwargs: resolver)
        monkeypatch.setattr("domains.check.lookup.time.sleep", lambda seconds: None)

        assert Lookup().query("example.com", dns.rdatatype.TXT) == Answer(failed=True)
        assert resolver.calls == 3

    def test_query__fails_at_once_on_another_dns_error(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "TXT", dns.exception.DNSException())

        assert lookup.query("example.com", dns.rdatatype.TXT) == Answer(failed=True)


class TestAccessors:
    def test_text__returns_none_for_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "TXT", dns.exception.DNSException())

        assert lookup.text("example.com") is None

    def test_text__returns_the_records(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"one"', '"two"')

        assert set(lookup.text("example.com")) == {"one", "two"}

    def test_addresses__combines_ipv4_and_ipv6(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "A", "192.0.2.1")
        dns_resolver.add("example.com", "AAAA", "2001:db8::1")

        assert lookup.addresses("example.com") == ("192.0.2.1", "2001:db8::1")

    def test_ptr__returns_none_for_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("1.2.0.192.in-addr.arpa", "PTR", dns.exception.DNSException())

        assert lookup.ptr("192.0.2.1") is None

    def test_ptr__strips_the_root_label(self, lookup, dns_resolver):
        dns_resolver.add("1.2.0.192.in-addr.arpa", "PTR", "mx.example.com.")

        assert lookup.ptr("192.0.2.1") == ("mx.example.com",)

    def test_mx__returns_failed_for_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "MX", dns.exception.DNSException())

        assert lookup.mx("example.com") == MxLookup(failed=True)

    def test_mx__reports_a_null_mx(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "MX", "0 .")

        mx = lookup.mx("example.com")

        assert mx.null
        assert mx.records == (MxRecord(0, ""),)

    def test_mx__returns_the_exchanges(self, lookup, dns_resolver):
        dns_resolver.add(
            "example.com", "MX", "10 mx1.example.com.", "20 mx2.example.com."
        )

        assert set(lookup.mx("example.com").exchanges) == {
            "mx1.example.com",
            "mx2.example.com",
        }

    def test_mx__returns_the_preferences(self, lookup, dns_resolver):
        dns_resolver.add(
            "example.com", "MX", "10 mx1.example.com.", "20 mx2.example.com."
        )

        assert lookup.mx("example.com").records == (
            MxRecord(10, "mx1.example.com"),
            MxRecord(20, "mx2.example.com"),
        )

    def test_mx__returns_an_empty_answer_without_records(self, lookup, dns_resolver):
        assert lookup.mx("example.com") == MxLookup()


class TestAsn:
    def test_fetch_asn__reads_the_asn_and_network(self, lookup, dns_resolver):
        dns_resolver.add(
            "1.2.0.192.origin.asn.cymru.com",
            "TXT",
            '"15169 | 192.0.2.1 | 192.0.2.0/24 | US | arin | 2000-03-30"',
        )
        dns_resolver.add(
            "AS15169.asn.cymru.com",
            "TXT",
            '"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"',
        )

        assert lookup.fetch_asn("192.0.2.1") == AsnRecord(
            asn="15169", country_code="US", network_name="Google LLC"
        )

    def test_fetch_asn__falls_back_to_the_origin_country(self, lookup, dns_resolver):
        dns_resolver.add(
            "1.2.0.192.origin.asn.cymru.com",
            "TXT",
            '"64500 | 192.0.2.1 | 192.0.2.0/24 | NL | ripencc | 2010-01-01"',
        )
        dns_resolver.fail("AS64500.asn.cymru.com", "TXT", dns.resolver.NXDOMAIN())

        assert lookup.fetch_asn("192.0.2.1").country_code == "NL"


class TestTtl:
    def test_ttl__returns_none_for_a_failed_lookup(self, lookup, dns_resolver):
        dns_resolver.fail("example.com", "TXT", dns.exception.DNSException())

        assert lookup.ttl("example.com", dns.rdatatype.TXT) is None

    def test_ttl__returns_none_without_records(self, lookup):
        assert lookup.ttl("example.com", dns.rdatatype.TXT) is None

    def test_ttl__returns_none_without_a_zone(self, lookup, dns_resolver):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"')

        assert lookup.ttl("example.com", dns.rdatatype.TXT) is None

    def test_ttl__keeps_the_resolver_ttl_when_the_zone_agrees(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("example.com", "TXT", '"v=spf1 -all"')
        dns_resolver.add("example.com", "NS", "ns1.example.com.")
        dns_resolver.add("ns1.example.com", "A", "8.8.8.8")

        assert lookup.ttl("example.com", dns.rdatatype.TXT) == dt.timedelta(minutes=30)

    def test_ttl__prefers_the_published_ttl(self, monkeypatch):
        recursive = StubResolver()
        recursive.add("example.com", "TXT", '"v=spf1 -all"')
        recursive.add("example.com", "NS", "ns1.example.com.")
        recursive.add("ns1.example.com", "A", "8.8.8.8")
        authority = Authority(7200)

        def factory(*args, **kwargs):
            return authority if kwargs.get("configure") is False else recursive

        monkeypatch.setattr(dns.resolver, "Resolver", factory)
        lookup = Lookup()

        assert lookup.ttl("example.com", dns.rdatatype.TXT) == dt.timedelta(hours=2)
        assert lookup.query("example.com", dns.rdatatype.TXT).ttl == dt.timedelta(
            hours=2
        )

    def test_ttl__reads_the_published_ttl_of_a_cname_target(self, monkeypatch):
        recursive = StubResolver()
        recursive.add("example.com", "CNAME", "target.example.net.")
        recursive.add("target.example.net", "TXT", '"v=spf1 -all"')
        recursive.add("target.example.net", "NS", "ns1.example.net.")
        recursive.add("ns1.example.net", "A", "8.8.8.8")
        authority = Authority(7200)

        def factory(*args, **kwargs):
            return authority if kwargs.get("configure") is False else recursive

        monkeypatch.setattr(dns.resolver, "Resolver", factory)
        lookup = Lookup()

        assert lookup.ttl("example.com", dns.rdatatype.TXT) == dt.timedelta(hours=2)
        assert authority.queries == ["target.example.net"]

    def test_authoritative_ttl__returns_none_without_a_zone(self, lookup):
        assert lookup.authoritative_ttl("example.com", dns.rdatatype.TXT) is None

    def test_authoritative_ttl__skips_a_nameserver_without_an_address(
        self, lookup, dns_resolver
    ):
        dns_resolver.add("example.com", "NS", "ns1.example.com.")

        assert lookup.authoritative_ttl("example.com", dns.rdatatype.TXT) is None
