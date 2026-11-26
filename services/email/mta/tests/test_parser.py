import datetime as dt
import json

import pytest
from django.utils import timezone

from services.email.mta.parser import parse_count, parse_datetime, parse_tls_report


class TestParseDatetime:
    def test_parse_datetime__keeps_the_utc_offset(self):
        assert parse_datetime("2026-01-15T00:00:00Z") == dt.datetime(
            2026, 1, 15, tzinfo=dt.UTC
        )

    def test_parse_datetime__localizes_a_naive_value(self):
        assert parse_datetime("2026-01-15T00:00:00") == timezone.make_aware(
            dt.datetime(2026, 1, 15)
        )

    def test_parse_datetime__returns_none_without_a_value(self):
        """A missing date range reaches the parser as None, not a string."""
        assert parse_datetime(None) is None

    def test_parse_datetime__raises_on_an_invalid_day(self):
        with pytest.raises(ValueError, match="day 30"):
            parse_datetime("2026-02-30T00:00:00")


class TestParseCount:
    def test_parse_count__returns_the_integer(self):
        assert parse_count("5") == 5

    def test_parse_count__returns_zero_without_a_value(self):
        assert parse_count(None) == 0

    def test_parse_count__returns_zero_for_a_non_numeric_string(self):
        assert parse_count("five") == 0

    def test_parse_count__returns_zero_for_an_infinite_value(self):
        """Python's json parser accepts Infinity, which int() rejects."""
        assert parse_count(float("inf")) == 0


class TestParseTlsReport:
    def test_parse_tls_report__converts_nested_dashed_keys(self):
        data = {
            "organization-name": "Acme Corp",
            "contact-info": "mailto:tlsreports@acme.com",
            "report-id": "r1",
            "date-range": {
                "start-datetime": "2026-01-14T00:00:00Z",
                "end-datetime": "2026-01-15T00:00:00Z",
            },
            "policies": [
                {
                    "policy": {"policy-type": "tlsa", "policy-domain": "example.com"},
                    "summary": {"successful-session-count": 3},
                    "failure-details": [{"result-type": "tlsa-invalid"}],
                }
            ],
        }

        meta, policies = parse_tls_report(json.dumps(data).encode())

        assert meta["reporting_org"] == "Acme Corp"
        assert meta["begin_at"] == dt.datetime(2026, 1, 14, tzinfo=dt.UTC)
        assert policies[0]["policy_type"] == "tlsa"
        assert policies[0]["failures"][0]["result_type"] == "tlsa-invalid"

    def test_parse_tls_report__returns_none_dates_without_a_date_range(self):
        meta, _ = parse_tls_report(
            b'{"organization-name": "Acme Corp", "report-id": "r1"}'
        )

        assert meta["begin_at"] is None
        assert meta["end_at"] is None

    def test_parse_tls_report__tolerates_null_policies(self):
        meta, policies = parse_tls_report(
            b'{"organization-name": "Acme Corp", "report-id": "r1", "policies": null}'
        )

        assert policies == []
        assert meta["reporting_org"] == "Acme Corp"

    def test_parse_tls_report__tolerates_null_failure_details(self):
        data = {
            "organization-name": "Acme Corp",
            "report-id": "r1",
            "policies": [
                {
                    "policy": {"policy-type": "sts", "policy-domain": "example.com"},
                    "summary": {
                        "successful-session-count": 3,
                        "failed-session-count": 0,
                    },
                    "failure-details": None,
                }
            ],
        }

        _, policies = parse_tls_report(json.dumps(data).encode())

        assert policies[0]["failures"] == []
