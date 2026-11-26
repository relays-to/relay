from django_letter.notifications import registry

from accounts.models import Organization
from domains.emails import DomainMonitorEmail, domain_monitor_notification
from domains.models import Domain, DomainCheck


def make_change(**fields):
    change = {
        "check_key": "spf",
        "check_label": "SPF",
        "subcheck_label": "Strict all",
        "detail": "Ends with ~all.",
        "hint": "End the SPF record with -all instead of ~all.",
        "previous_status": "pass",
        "current_status": "fail",
    }
    change.update(fields)
    return change


def make_fixed_change(**fields):
    return make_change(
        previous_status="fail",
        current_status="pass",
        hint="",
        **fields,
    )


def make_email(*, changes=None):
    return DomainMonitorEmail(
        domain=Domain(pk=0, name="acme.com", org=Organization(slug="acme")),
        domain_check=DomainCheck(
            name="acme.com",
            penalty=2,
            status=DomainCheck.Status.COMPLETE,
        ),
        changes=[make_change()] if changes is None else changes,
        language="en-us",
    )


class TestDomainMonitorNotification:
    def test_notification__is_registered(self):
        assert registry["domain-monitor"] is domain_monitor_notification

    def test_notification__is_attached_to_the_email(self):
        assert DomainMonitorEmail.notification is domain_monitor_notification


class TestDomainMonitorEmailContext:
    def make_context(self, changes):
        email = make_email(changes=changes)
        return email.get_context_data()

    def test_context__counts_the_broken_and_fixed_changes(self):
        context = self.make_context([make_change(), make_fixed_change()])

        assert context["change_count"] == 2
        assert context["broken_count"] == 1
        assert context["fixed_count"] == 1

    def test_context__drops_a_check_label_the_subcheck_repeats(self):
        context = self.make_context(
            [make_change(check_label="SPF", subcheck_label="SPF record")]
        )

        assert context["changes"][0]["check_label"] == ""

    def test_context__keeps_a_check_label_the_subcheck_does_not_repeat(self):
        context = self.make_context(
            [make_change(check_label="SPF", subcheck_label="Strict all")]
        )

        assert context["changes"][0]["check_label"] == "SPF"

    def test_context__carries_the_domain_and_its_score(self):
        context = self.make_context([make_change()])

        assert context["domain_name"] == "acme.com"
        assert context["tier"] == "A"
        assert context["tier_variant"] == "success"
        assert context["detail_url"] == "/org/acme/email/domains/0/"


class TestDomainMonitorEmailSubject:
    def test_subject__names_a_single_broken_check(self):
        email = make_email()
        email.render()

        assert email.subject == "acme.com: Strict all needs attention"

    def test_subject__names_a_single_recovery(self):
        email = make_email(changes=[make_fixed_change()])
        email.render()

        assert email.subject == "acme.com: Strict all is fixed"

    def test_subject__counts_several_changes(self):
        email = make_email(changes=[make_change(), make_fixed_change()])
        email.render()

        assert email.subject == "acme.com: 2 changes"

    def test_preheader__offers_the_fix_while_something_broke(self):
        email = make_email()

        assert str(email.get_preheader(**email.get_context_data())) == (
            "See what changed and how to fix it."
        )

    def test_preheader__celebrates_a_full_recovery(self):
        email = make_email(changes=[make_fixed_change()])

        assert str(email.get_preheader(**email.get_context_data())) == (
            "Everything passes again."
        )


class TestDomainMonitorEmailRender:
    def test_render__shows_the_detail_and_the_hint_of_a_regression(self):
        email = make_email()
        email.render()

        assert "Ends with ~all." in email.html
        assert "End the SPF record with -all instead of ~all." in email.html
        assert ">acme.com</div>" in email.html

    def test_render__drops_a_check_label_the_subcheck_repeats(self):
        email = make_email(
            changes=[make_change(check_label="SPF", subcheck_label="SPF record")]
        )
        email.render()

        assert "SPF record" in email.html
        assert '<div class="monitor-change-kicker">' not in email.html

    def test_render__hides_the_detail_of_a_recovery(self):
        email = make_email(changes=[make_fixed_change(detail="Ends with -all.")])
        email.render()

        assert "Ends with -all." not in email.html
        assert "Strict all" in email.html

    def test_render_preview__renders_without_arguments(self):
        email = DomainMonitorEmail.render_preview()

        assert email.subject == "acme.com: 2 changes"
        assert ">acme.com</div>" in email.html

    def test_render_preview__uses_the_given_changes(self):
        email = DomainMonitorEmail.render_preview(changes=[make_change()])

        assert email.subject == "acme.com: Strict all needs attention"
