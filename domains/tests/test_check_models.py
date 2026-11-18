import datetime

import pytest
from django.utils import timezone

from domains.check.evaluation import Check, CheckResult, MxCheck, SubCheck
from domains.check.tiers import Tier
from domains.models import DomainCheck


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
            modified_at=timezone.now() - datetime.timedelta(days=2),
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
            modified_at=timezone.now() - datetime.timedelta(days=2),
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
