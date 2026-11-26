import datetime as dt

import pytest
from django.utils import timezone

from domains.check.evaluation import (
    Check,
    CheckResult,
    MtaStsCheck,
    MxCheck,
    SubCheck,
)
from domains.check.tiers import Tier
from domains.models import Domain, DomainCheck


def make_row(key="mx", subchecks=(), **kwargs):
    return {
        "key": key,
        "label": key.upper(),
        "detail": "",
        "subchecks": list(subchecks),
    } | kwargs


def make_check(**kwargs):
    fields = {
        "name": "example.com",
        "status": DomainCheck.Status.COMPLETE,
        "penalty": 0,
        "checks": [],
    }
    fields.update(kwargs)
    return DomainCheck.objects.create(**fields)


class TestDomainCheckBasics:
    def test_str__returns_the_name(self):
        assert str(DomainCheck(name="example.com")) == "example.com"

    def test_repr__returns_the_primary_key(self):
        assert repr(DomainCheck(pk=7)) == "<DomainCheck 7>"

    def test_get_absolute_url__points_at_the_detail_page(self):
        assert (
            DomainCheck(name="example.com").get_absolute_url()
            == "/domain-check/example.com/"
        )


class TestIsStale:
    def test_is_stale__failed_check(self):
        check = DomainCheck(
            status=DomainCheck.Status.FAILED, modified_at=timezone.now()
        )

        assert check.is_stale is True

    def test_is_stale__pending_check(self):
        check = DomainCheck(status=DomainCheck.Status.PENDING)

        assert check.is_stale is True

    def test_is_stale__running_check_counts_from_modified_at(self):
        check = DomainCheck(
            status=DomainCheck.Status.RUNNING, modified_at=timezone.now()
        )

        assert check.is_stale is False

    def test_is_stale__stale_running_check(self):
        check = DomainCheck(
            status=DomainCheck.Status.RUNNING,
            modified_at=timezone.now() - dt.timedelta(days=2),
        )

        assert check.is_stale is True

    def test_is_stale__fresh_complete_check(self):
        check = DomainCheck(
            status=DomainCheck.Status.COMPLETE, modified_at=timezone.now()
        )

        assert check.is_stale is False

    def test_is_stale__old_complete_check(self):
        check = DomainCheck(
            status=DomainCheck.Status.COMPLETE,
            modified_at=timezone.now() - dt.timedelta(days=2),
        )

        assert check.is_stale is True


class TestCheckRows:
    def test_build_check_row__adds_the_slug_and_hints(self):
        row = DomainCheck.build_check_row(
            make_row(
                subchecks=[
                    {"label": "MX record", "status": "fail", "detail": "none"},
                    {"label": "MX TTL", "status": "pass", "detail": "an hour"},
                ]
            )
        )

        assert row["slug"] == "mx"
        assert row["subchecks"][0] == {
            "label": "MX record",
            "status": "fail",
            "detail": "none",
            "severity": "broken",
            "hint": MxCheck.HINTS["MX record"],
        }
        assert row["subchecks"][1]["hint"] == Check.TTL_HINT
        assert row["issue_count"] == 1

    def test_build_check_row__keeps_a_given_severity(self):
        row = DomainCheck.build_check_row(
            make_row(
                subchecks=[
                    {"label": "Strict all", "status": "fail", "severity": "weak"}
                ]
            )
        )

        assert row["subchecks"][0]["severity"] == "weak"

    def test_build_check_row__upgrades_a_legacy_weak_starttls_finding(self):
        row = DomainCheck.build_check_row(
            make_row(
                key="mta_sts",
                subchecks=[
                    {
                        "label": "STARTTLS",
                        "status": "fail",
                        "detail": (
                            "mx.example.com: TLSv1.3, x25519, RSA 2048, "
                            "no PQ key exchange"
                        ),
                        "severity": "weak",
                    }
                ],
            )
        )

        subcheck = row["subchecks"][0]
        assert subcheck["label"] == "Post-quantum key exchange"
        assert subcheck["detail"] == "mx.example.com: TLSv1.3, x25519, RSA 2048"
        assert subcheck["hint"] == MtaStsCheck.HINTS["Post-quantum key exchange"]

    def test_build_check_row__copes_without_subchecks(self):
        row = DomainCheck.build_check_row({"key": "mx", "label": "MX", "detail": ""})

        assert row["subchecks"] == []
        assert row["issue_count"] == 0

    def test_build_check_row__does_not_count_passes_or_skips(self):
        row = DomainCheck.build_check_row(
            make_row(
                subchecks=[
                    {"label": "a", "status": "pass"},
                    {"label": "b", "status": "skip"},
                    {"label": "c", "status": "partial"},
                ]
            )
        )

        assert row["issue_count"] == 1

    def test_check_rows__drops_unknown_checks(self):
        check = DomainCheck(
            checks=[make_row(), make_row(key="unknown")],
        )

        assert [row["key"] for row in check.check_rows] == ["mx"]

    def test_issue_count__sums_every_row(self):
        check = DomainCheck(
            checks=[
                make_row(subchecks=[{"label": "a", "status": "fail"}]),
                make_row(key="spf", subchecks=[{"label": "b", "status": "fail"}]),
            ]
        )

        assert check.issue_count == 2


class TestJurisdictionFlags:
    def test_jurisdiction_flags__merges_mx_and_spf_sources(self):
        check = DomainCheck(
            name="example.com",
            checks=[
                {
                    "key": "mx",
                    "metadata": {
                        "jurisdiction": {
                            "providers": [
                                {
                                    "provider_name": "Microsoft 365",
                                    "country_code": "US",
                                    "exchange": "example.mail.protection.outlook.com",
                                }
                            ],
                            "networks": [
                                {
                                    "asn": "8075",
                                    "network_name": "MICROSOFT-CORP-MSN-AS-BLOCK",
                                    "country_code": "US",
                                    "address": "192.0.2.1",
                                }
                            ],
                            "country_codes": ["US"],
                        }
                    },
                },
                {
                    "key": "spf",
                    "metadata": {
                        "jurisdiction": {
                            "providers": [],
                            "networks": [
                                {
                                    "asn": "64500",
                                    "network_name": "EXAMPLE-NET",
                                    "country_code": "DE",
                                    "address": "198.51.100.1",
                                }
                            ],
                            "country_codes": ["DE"],
                        }
                    },
                },
            ],
        )

        flags = check.jurisdiction_flags

        assert [flag["country_code"] for flag in flags] == ["US", "DE"]
        assert flags[0]["country_name"] == "United States"
        assert flags[0]["sources"] == (
            "Microsoft 365",
            "MICROSOFT-CORP-MSN-AS-BLOCK (AS8075)",
        )
        assert flags[1]["sources"] == ("EXAMPLE-NET (AS64500)",)
        assert flags[0]["flag_url"] == "https://flagcdn.com/us.svg"

    def test_jurisdiction_flags__ignores_checks_without_a_jurisdiction(self):
        assert (
            DomainCheck(name="example.com", checks=[{"key": "mx"}]).jurisdiction_flags
            == ()
        )

    def test_jurisdiction_flags__skips_codes_that_are_not_countries(self):
        check = DomainCheck(
            checks=[
                {
                    "key": "mx",
                    "metadata": {
                        "jurisdiction": {
                            "networks": [
                                {
                                    "asn": "22612",
                                    "network_name": "",
                                    "country_code": "ARIN",
                                    "address": "192.0.2.1",
                                },
                                {
                                    "asn": "22612",
                                    "network_name": "Namecheap, Inc.",
                                    "country_code": "US",
                                    "address": "192.0.2.2",
                                },
                            ],
                            "country_codes": ["ARIN", "US"],
                        }
                    },
                }
            ],
        )

        assert [flag["country_code"] for flag in check.jurisdiction_flags] == ["US"]


class TestPenalty:
    def test_penalty_for__is_zero_without_failures(self):
        assert DomainCheck.penalty_for([make_row()]) == 0

    def test_penalty_for__a_broken_failure_costs_two(self):
        row = make_row(subchecks=[{"label": "a", "status": "fail"}])

        assert DomainCheck.penalty_for([row]) == 2

    def test_penalty_for__a_weak_failure_costs_one(self):
        row = make_row(subchecks=[{"label": "a", "status": "fail", "severity": "weak"}])

        assert DomainCheck.penalty_for([row]) == 1

    def test_penalty_for__sums_the_failures(self):
        row = make_row(
            subchecks=[
                {"label": "a", "status": "fail"},
                {"label": "b", "status": "fail", "severity": "weak"},
            ]
        )

        assert DomainCheck.penalty_for([row]) == 3

    def test_penalty_for__defaults_a_missing_severity_to_broken(self):
        row = make_row(subchecks=[{"label": "a", "status": "fail"}])

        assert DomainCheck.penalty_for([row]) == 2

    def test_penalty_for__a_blocking_failure_pins_the_tier(self):
        row = make_row(
            subchecks=[
                {"label": "a", "status": "fail", "severity": "blocking"},
                {"label": "b", "status": "fail"},
            ]
        )

        assert DomainCheck.penalty_for([row]) == len(Tier) - 1


class TestCopy:
    def test_issue_phrase__all_checks_pass(self):
        assert DomainCheck(checks=[]).issue_phrase == "All checks pass"

    def test_issue_phrase__one_issue(self):
        check = DomainCheck(
            checks=[make_row(subchecks=[{"label": "a", "status": "fail"}])]
        )

        assert check.issue_phrase == "1 issue needs attention"

    def test_issue_phrase__several_issues(self):
        check = DomainCheck(
            checks=[
                make_row(
                    subchecks=[
                        {"label": "a", "status": "fail"},
                        {"label": "b", "status": "fail"},
                    ]
                )
            ]
        )

        assert check.issue_phrase == "2 issues need attention"

    def test_status_line__complete(self):
        assert DomainCheck(status=DomainCheck.Status.COMPLETE).status_line == (
            "All checks pass"
        )

    def test_status_line__failed(self):
        assert (
            DomainCheck(status=DomainCheck.Status.FAILED).status_line
            == "The last check failed"
        )

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING]
    )
    def test_status_line__in_progress(self, status):
        assert DomainCheck(status=status).status_line == "Check in progress"


class TestTier:
    def test_tier__starts_at_s(self):
        assert DomainCheck(penalty=0).tier is Tier.S

    def test_tier__caps_a_high_penalty(self):
        assert DomainCheck(penalty=99).tier is Tier.F

    def test_tier__maps_every_half_step(self):
        assert DomainCheck(penalty=1).tier is Tier.A_PLUS

    def test_tier_letter__complete(self):
        assert (
            DomainCheck(status=DomainCheck.Status.COMPLETE, penalty=0).tier_letter
            == "S"
        )

    def test_tier_letter__dash_while_incomplete(self):
        assert DomainCheck(
            status=DomainCheck.Status.RUNNING, penalty=0
        ).tier_letter == ("\u2013")

    def test_tier_variant__follows_the_tier(self):
        assert DomainCheck(penalty=0).tier_variant == "primary"


@pytest.mark.django_db
class TestStore:
    def test_store__leaves_a_check_that_is_not_running(self):
        check = make_check(status=DomainCheck.Status.COMPLETE, checks=[make_row()])

        DomainCheck.store("example.com", [])

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.COMPLETE
        assert check.checks == [make_row()]

    def test_store__merges_a_partial_result(self):
        check = make_check(status=DomainCheck.Status.RUNNING)

        DomainCheck.store("example.com", [CheckResult("mx", "MX", "done")])

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.RUNNING
        assert check.checks == [
            {
                "key": "mx",
                "label": "MX",
                "detail": "done",
                "subchecks": [],
                "status": "partial",
            }
        ]

    def test_store__completes_when_every_check_answered(self):
        check = make_check(status=DomainCheck.Status.RUNNING)

        results = [CheckResult(key, key, "done") for key in Check.order()]
        DomainCheck.store("example.com", results)

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.COMPLETE
        assert check.penalty == 0
        assert [row["key"] for row in check.checks] == list(Check.order())

    def test_store__orders_the_rows_and_drops_unknown_keys(self):
        check = make_check(
            status=DomainCheck.Status.RUNNING,
            checks=[make_row(key="unknown"), make_row(key="spf")],
        )

        DomainCheck.store("example.com", [CheckResult("mx", "MX", "done")])

        check.refresh_from_db()
        assert [row["key"] for row in check.checks] == ["mx", "spf"]

    def test_store__keeps_the_subchecks(self):
        check = make_check(status=DomainCheck.Status.RUNNING)
        result = CheckResult(
            "mx", "MX", "done", (SubCheck("MX record", "pass", "one"),)
        )

        DomainCheck.store("example.com", [result])

        check.refresh_from_db()
        assert check.checks[0]["subchecks"] == [
            {
                "label": "MX record",
                "status": "pass",
                "detail": "one",
                "severity": "broken",
                "addresses": [],
            }
        ]


class TestIsStaleMonitored:
    def test_is_stale__monitored_check_is_fresh_within_the_hour(self):
        check = DomainCheck(
            status=DomainCheck.Status.COMPLETE,
            domain_id=1,
            modified_at=timezone.now() - dt.timedelta(minutes=30),
        )

        assert check.is_stale is False

    def test_is_stale__monitored_check_is_stale_after_the_hour(self):
        check = DomainCheck(
            status=DomainCheck.Status.COMPLETE,
            domain_id=1,
            modified_at=timezone.now() - dt.timedelta(hours=2),
        )

        assert check.is_stale is True


@pytest.mark.django_db
class TestForDomain:
    def test_for_domain__creates_and_links_a_missing_check(self, org):
        domain = Domain.objects.create(name="example.com", org=org)
        DomainCheck.objects.all().delete()

        domain_check = DomainCheck.for_domain(domain)

        assert domain_check.name == "example.com"
        assert domain_check.domain == domain
        assert domain_check.status == DomainCheck.Status.PENDING

    def test_for_domain__returns_an_existing_linked_check(self, org):
        domain = Domain.objects.create(name="example.com", org=org)
        existing = DomainCheck.objects.get(name="example.com")

        domain_check = DomainCheck.for_domain(domain)

        assert domain_check.pk == existing.pk
        assert domain_check.domain == domain

    def test_for_domain__links_a_complete_free_check_without_a_baseline(self, org):
        domain = Domain.objects.create(name="example.com", org=org)
        DomainCheck.objects.all().delete()
        checks = [make_row(subchecks=[{"label": "MX record", "status": "pass"}])]
        free_check = DomainCheck.objects.create(
            name="example.com",
            status=DomainCheck.Status.COMPLETE,
            checks=checks,
        )

        domain_check = DomainCheck.for_domain(domain)

        free_check.refresh_from_db()
        assert domain_check.pk == free_check.pk
        assert free_check.domain == domain
        assert free_check.checks == checks
        assert free_check.previous_checks == []

    def test_for_domain__keeps_an_existing_baseline(self, org):
        domain = Domain.objects.create(name="example.com", org=org)
        DomainCheck.objects.all().delete()
        previous = [make_row()]
        free_check = DomainCheck.objects.create(
            name="example.com",
            status=DomainCheck.Status.COMPLETE,
            checks=[make_row(key="spf")],
            previous_checks=previous,
        )

        DomainCheck.for_domain(domain)

        free_check.refresh_from_db()
        assert free_check.previous_checks == previous

    def test_for_domain__links_an_unfinished_free_check_without_a_baseline(self, org):
        domain = Domain.objects.create(name="example.com", org=org)
        DomainCheck.objects.all().delete()
        free_check = DomainCheck.objects.create(
            name="example.com",
            status=DomainCheck.Status.PENDING,
            checks=[make_row()],
        )

        DomainCheck.for_domain(domain)

        free_check.refresh_from_db()
        assert free_check.domain == domain
        assert free_check.previous_checks == []


class TestFlattenChecks:
    def test_flatten_checks__keys_each_subcheck_by_check_and_position(self):
        rows = [
            make_row(
                key="mx",
                subchecks=[
                    {"label": "MX record", "status": "pass", "detail": "one"},
                    {"label": "STARTTLS", "status": "fail", "detail": "two"},
                ],
            ),
            make_row(
                key="spf",
                subchecks=[{"label": "STARTTLS", "status": "pass", "detail": "three"}],
            ),
        ]

        assert DomainCheck.flatten_checks(rows) == {
            ("mx", 0): ("MX", "MX record", "pass", "one"),
            ("mx", 1): ("MX", "STARTTLS", "fail", "two"),
            ("spf", 0): ("SPF", "STARTTLS", "pass", "three"),
        }

    def test_flatten_checks__defaults_a_missing_detail(self):
        rows = [make_row(subchecks=[{"label": "MX record", "status": "pass"}])]

        assert DomainCheck.flatten_checks(rows)[("mx", 0)] == (
            "MX",
            "MX record",
            "pass",
            "",
        )


class TestCalculateChanges:
    def make_changes(self, previous, current):
        return DomainCheck(checks=current).calculate_changes(previous)

    def test_calculate_changes__reports_a_regression_with_its_hint(self):
        previous = [
            make_row(key="spf", subchecks=[{"label": "Strict all", "status": "pass"}])
        ]
        current = [
            make_row(
                key="spf",
                subchecks=[{"label": "Strict all", "status": "fail", "detail": "~all"}],
            )
        ]

        changes = self.make_changes(previous, current)

        assert changes == [
            {
                "check_key": "spf",
                "check_label": "SPF",
                "subcheck_label": "Strict all",
                "detail": "~all",
                "hint": ("End the SPF record with -all instead of ~all."),
                "previous_status": "pass",
                "current_status": "fail",
            }
        ]

    def test_calculate_changes__reports_a_recovery_without_a_hint(self):
        previous = [make_row(subchecks=[{"label": "MX record", "status": "fail"}])]
        current = [make_row(subchecks=[{"label": "MX record", "status": "pass"}])]

        changes = self.make_changes(previous, current)

        assert changes == [
            {
                "check_key": "mx",
                "check_label": "MX",
                "subcheck_label": "MX record",
                "detail": "",
                "hint": "",
                "previous_status": "fail",
                "current_status": "pass",
            }
        ]

    def test_calculate_changes__reports_a_newly_failing_subcheck(self):
        previous = [make_row(subchecks=[])]
        current = [make_row(subchecks=[{"label": "MX record", "status": "fail"}])]

        changes = self.make_changes(previous, current)

        assert [
            (change["previous_status"], change["current_status"]) for change in changes
        ] == [(None, "fail")]

    def test_calculate_changes__stays_silent_without_a_status_flip(self):
        previous = [
            make_row(
                subchecks=[
                    {"label": "MX record", "status": "pass"},
                    {"label": "MX TTL", "status": "fail"},
                ]
            )
        ]
        current = [
            make_row(
                subchecks=[
                    {"label": "MX record", "status": "pass"},
                    {"label": "MX TTL", "status": "fail"},
                ]
            )
        ]

        assert self.make_changes(previous, current) == []

    def test_calculate_changes__keeps_subchecks_apart_by_position(self):
        previous = [
            make_row(
                subchecks=[
                    {"label": "STARTTLS", "status": "fail"},
                    {"label": "STARTTLS", "status": "pass"},
                ]
            )
        ]
        current = [
            make_row(
                subchecks=[
                    {"label": "STARTTLS", "status": "fail"},
                    {"label": "STARTTLS", "status": "fail"},
                ]
            )
        ]

        changes = self.make_changes(previous, current)

        assert len(changes) == 1
        assert changes[0]["previous_status"] == "pass"
        assert changes[0]["current_status"] == "fail"


@pytest.mark.django_db
class TestStoreMonitored:
    def make_linked_check(self, org, **kwargs):
        Domain.objects.create(name="example.com", org=org)
        fields = {
            "status": DomainCheck.Status.RUNNING,
            "checks": [],
            "previous_checks": [],
        }
        fields.update(kwargs)
        DomainCheck.objects.filter(name="example.com").update(**fields)
        return DomainCheck.objects.get(name="example.com")

    def test_store__first_run_only_stores_the_baseline(self, org):
        check = self.make_linked_check(org)

        changes = DomainCheck.store(
            "example.com", [CheckResult(key, key, "done") for key in Check.order()]
        )

        check.refresh_from_db()
        assert changes == []
        assert check.previous_checks == check.checks

    def test_store__reports_the_changes_against_the_baseline(self, org):
        baseline = [
            make_row(key="spf", subchecks=[{"label": "Strict all", "status": "pass"}])
        ]
        check = self.make_linked_check(org, previous_checks=baseline)

        changes = DomainCheck.store(
            "example.com",
            [
                CheckResult(key, key, "done")
                if key != "spf"
                else CheckResult(
                    "spf",
                    "SPF",
                    "done",
                    (SubCheck("Strict all", "fail", "~all"),),
                )
                for key in Check.order()
            ],
        )

        check.refresh_from_db()
        assert [
            (
                change["subcheck_label"],
                change["previous_status"],
                change["current_status"],
            )
            for change in changes
        ] == [("Strict all", "pass", "fail")]
        assert check.previous_checks == check.checks

    def test_store__an_unmonitored_run_never_reports_changes(self):
        check = make_check(status=DomainCheck.Status.RUNNING)

        changes = DomainCheck.store(
            "example.com", [CheckResult(key, key, "done") for key in Check.order()]
        )

        check.refresh_from_db()
        assert changes == []

    def test_store__an_unfinished_run_returns_none(self):
        make_check(status=DomainCheck.Status.RUNNING)

        assert DomainCheck.store("example.com", []) is None
