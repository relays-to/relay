import datetime as dt
import gzip
import logging
from email.message import EmailMessage

import pytest
from django.core.files.base import ContentFile

from domains.models import Domain
from services.email.dmarc.models import DmarcFailureReport, DmarcRecord, DmarcReport
from services.email.dmarc.tasks import parse_dmarc_failure_report, parse_dmarc_report

SAMPLE_XML = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply@google.com</email>
    <report_id>12345</report_id>
    <date_range>
      <begin>1704067200</begin>
      <end>1704153600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.168.1.1</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>"""

EMPTY_XML = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply@google.com</email>
    <report_id>empty</report_id>
  </report_metadata>
</feedback>"""


def make_aggregate_email(xml_bytes):
    """Return a raw email carrying a gzipped DMARC aggregate report."""
    message = EmailMessage()
    message["From"] = "reporter@example.com"
    message["To"] = "dmarc@example.com"
    message["Subject"] = "DMARC Report"
    message.set_content("Report body")
    message.add_attachment(
        gzip.compress(xml_bytes),
        maintype="application",
        subtype="gzip",
        filename="report.xml.gz",
    )
    return message.as_bytes()


def make_arf_email():
    """Return a raw ARF email carrying a DMARC forensic report."""
    message = EmailMessage()
    message["From"] = "reporter@example.com"
    message["To"] = "dmarc@example.com"
    message["Subject"] = "RUF Report"
    message.set_content("This is a report")
    message.add_attachment(
        b"Feedback-Type: auth-failure\n"
        b"Source-IP: 10.0.0.1\n"
        b"Original-Mail-From: sender@example.com\n"
        b"Original-Rcpt-To: victim@example.com\n"
        b"Delivery-Result: policy\n",
        maintype="message",
        subtype="feedback-report",
    )
    message.add_attachment(
        b"From: sender@example.com\r\nTo: victim@example.com\r\n",
        maintype="text",
        subtype="rfc822-headers",
    )
    return message.as_bytes()


def make_plain_email():
    """Return a raw email that carries no report content."""
    message = EmailMessage()
    message["From"] = "reporter@example.com"
    message["To"] = "dmarc@example.com"
    message["Subject"] = "No report"
    message.set_content("No attachment")
    return message.as_bytes()


def make_stored_report(model, org, raw_bytes, **fields):
    """Store a received report row with the given raw body."""
    report = model(
        org=org,
        domain=Domain.objects.create(name="example.com", org=org),
        receiving_domain="example.com",
        mail_from="reporter@example.com",
        rcpt_to="dmarc@example.com",
        subject="Report",
        message_id="<report@example.com>",
        **fields,
    )
    report.raw_body.save("report.eml", ContentFile(raw_bytes), save=False)
    report.save()
    return report


@pytest.mark.django_db
class TestParseDmarcReport:
    def test_parse_dmarc_report__stores_metadata_and_records(self, org):
        report = make_stored_report(
            DmarcReport, org, make_aggregate_email(SAMPLE_XML), report_id=""
        )

        parse_dmarc_report.func(report_pk=str(report.pk))

        report.refresh_from_db()
        assert report.reporting_org == "google.com"
        assert report.reporting_email == "noreply@google.com"
        assert report.report_id == "12345"
        assert report.begin_at == dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
        record = DmarcRecord.objects.get(report=report)
        assert record.source_ip_address == "192.168.1.1"
        assert record.count == 3
        assert record.disposition == "none"

    def test_parse_dmarc_report__stores_metadata_without_records(self, org):
        report = make_stored_report(
            DmarcReport, org, make_aggregate_email(EMPTY_XML), report_id=""
        )

        parse_dmarc_report.func(report_pk=str(report.pk))

        report.refresh_from_db()
        assert report.report_id == "empty"
        assert report.begin_at is None
        assert not DmarcRecord.objects.filter(report=report).exists()

    def test_parse_dmarc_report__logs_malformed_xml(self, org, caplog):
        report = make_stored_report(
            DmarcReport, org, make_aggregate_email(b"<feedback>"), report_id=""
        )

        with caplog.at_level(logging.WARNING):
            parse_dmarc_report.func(report_pk=str(report.pk))

        assert str(report.pk) in caplog.text
        assert "could not be parsed" in caplog.text
        report.refresh_from_db()
        assert report.reporting_org == ""
        assert not DmarcRecord.objects.filter(report=report).exists()

    def test_parse_dmarc_report__logs_missing_attachment(self, org, caplog):
        report = make_stored_report(DmarcReport, org, make_plain_email(), report_id="")

        with caplog.at_level(logging.WARNING):
            parse_dmarc_report.func(report_pk=str(report.pk))

        assert "could not be parsed" in caplog.text
        report.refresh_from_db()
        assert report.report_id == ""
        assert not DmarcRecord.objects.filter(report=report).exists()


@pytest.mark.django_db
class TestParseDmarcFailureReport:
    def test_parse_dmarc_failure_report__stores_the_parsed_fields(self, org):
        report = make_stored_report(DmarcFailureReport, org, make_arf_email())

        parse_dmarc_failure_report.func(report_pk=str(report.pk))

        report.refresh_from_db()
        assert report.source_ip_address == "10.0.0.1"
        assert report.original_mail_from == "sender@example.com"
        assert report.original_rcpt_to == "victim@example.com"
        assert report.delivery_result == "policy"
        assert "From: sender@example.com" in report.original_headers

    def test_parse_dmarc_failure_report__logs_missing_arf_content(self, org, caplog):
        report = make_stored_report(DmarcFailureReport, org, make_plain_email())

        with caplog.at_level(logging.WARNING):
            parse_dmarc_failure_report.func(report_pk=str(report.pk))

        assert "could not be parsed" in caplog.text
        report.refresh_from_db()
        assert report.source_ip_address is None
        assert report.original_mail_from == ""
