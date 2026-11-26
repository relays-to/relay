import typing

from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from django_letter import TemplateEmail
from django_letter.notifications import Notification

from accounts.models import Organization

from .models import Domain, DomainCheck

domain_monitor_notification = Notification(
    "domain-monitor",
    _("Domain monitoring"),
    _("A note when a DNS check on one of your domains changes."),
)


@domain_monitor_notification
class DomainMonitorEmail(TemplateEmail):
    """Report which checks broke or recovered since the previous run."""

    template_name = "emails/domain_monitor.html"
    subject = _("%(domain_name)s: %(change_count)d changes")
    subject_broke = _("%(domain_name)s: %(subcheck_label)s needs attention")
    subject_fixed = _("%(domain_name)s: %(subcheck_label)s is fixed")

    def __init__(
        self,
        *,
        domain: Domain,
        domain_check: DomainCheck,
        changes: list[dict],
        **kwargs,
    ) -> None:
        self.domain = domain
        self.domain_check = domain_check
        self.changes = changes
        super().__init__(**kwargs)

    @classmethod
    def render_preview(
        cls,
        request: HttpRequest | None = None,
        *,
        context: dict[str, typing.Any] | None = None,
        language: str | None = None,
        **kwargs,
    ) -> TemplateEmail:
        kwargs.setdefault(
            "domain",
            Domain(pk=0, name="acme.com", org=Organization(slug="acme")),
        )
        kwargs.setdefault(
            "domain_check",
            DomainCheck(
                name="acme.com",
                penalty=2,
                status=DomainCheck.Status.COMPLETE,
            ),
        )
        kwargs.setdefault(
            "changes",
            [
                {
                    "check_key": "spf",
                    "check_label": "SPF",
                    "subcheck_label": "Strict all",
                    "detail": "Ends with ~all.",
                    "hint": "End the SPF record with -all instead of ~all.",
                    "previous_status": "pass",
                    "current_status": "fail",
                },
                {
                    "check_key": "dmarc",
                    "check_label": "DMARC",
                    "subcheck_label": "DMARC record",
                    "detail": "DMARC record found.",
                    "hint": "",
                    "previous_status": "fail",
                    "current_status": "pass",
                },
            ],
        )
        return super().render_preview(
            request, context=context, language=language, **kwargs
        )

    def get_context_data(self) -> dict[str, typing.Any]:
        changes = [
            change
            | {
                "check_label": (
                    ""
                    if change["check_label"].casefold()
                    in change["subcheck_label"].casefold()
                    else change["check_label"]
                )
            }
            for change in self.changes
        ]
        broken_count = sum(change["current_status"] == "fail" for change in changes)
        return super().get_context_data() | {
            "domain": self.domain,
            "domain_name": self.domain.name,
            "changes": changes,
            "change_count": len(changes),
            "broken_count": broken_count,
            "fixed_count": len(changes) - broken_count,
            "tier": self.domain_check.tier,
            "tier_variant": self.domain_check.tier_variant,
            "detail_url": self.domain.get_absolute_url(),
        }

    def get_preheader(self, **context) -> str:
        if context["broken_count"]:
            return _("See what changed and how to fix it.")
        return _("Everything passes again.")

    def get_subject(self, **context) -> str:
        match context["changes"]:
            case [change] if change["current_status"] == "fail":
                return self.subject_broke % (context | change)
            case [change]:
                return self.subject_fixed % (context | change)
            case _:
                return super().get_subject(**context)
