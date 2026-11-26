"""Parse TLS-RPT JSON reports (RFC 8460)."""

import json

from django.utils import dateparse, timezone


def parse_datetime(value):
    """
    Return an aware datetime from an RFC 3339 string, or None.

    Raises `ValueError` for a well-formed but invalid datetime.
    """
    try:
        parsed = dateparse.parse_datetime(value)
    except TypeError:
        parsed = None
    return (
        timezone.make_aware(parsed)
        if parsed is not None and timezone.is_naive(parsed)
        else parsed
    )


def parse_count(value):
    """Return a session count as an int, or 0 when missing or malformed."""
    try:
        count = int(value)
    except TypeError, ValueError, OverflowError:
        count = 0
    return count


def parse_tls_report(data):
    """
    Return report metadata and policy summaries from a TLS-RPT JSON byte string.

    Missing fields fall back to the RFC 8460 defaults.
    """
    report = json.loads(
        data,
        object_hook=lambda item: {
            key.replace("-", "_"): value for key, value in item.items()
        },
    )
    date_range = report.get("date_range") or {}
    metadata = {
        "reporting_org": report.get("organization_name", ""),
        "reporting_email": report.get("contact_info", ""),
        "report_id": report.get("report_id", ""),
        "begin_at": parse_datetime(date_range.get("start_datetime")),
        "end_at": parse_datetime(date_range.get("end_datetime")),
    }
    policies = []
    for entry in report.get("policies") or []:
        policy = entry.get("policy") or {}
        summary = entry.get("summary") or {}
        policies.append(
            {
                "policy_type": policy.get("policy_type", "sts"),
                "policy_domain": policy.get("policy_domain", ""),
                "successful_session_count": parse_count(
                    summary.get("successful_session_count")
                ),
                "failed_session_count": parse_count(
                    summary.get("failed_session_count")
                ),
                "failures": [
                    {
                        "result_type": detail.get("result_type", "other"),
                        "sending_mta_ip_address": detail.get("sending_mta_ip", ""),
                        "receiving_mx_hostname": detail.get(
                            "receiving_mx_hostname", ""
                        ),
                        "receiving_mx_ip_address": detail.get("receiving_mx_ip"),
                        "count": parse_count(detail.get("failed_session_count")),
                        "additional_info": detail.get("additional_information", ""),
                    }
                    for detail in entry.get("failure_details") or []
                ],
            }
        )
    return metadata, policies
