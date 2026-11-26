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
    template_name = "emails/domain_monitor.html"
    subject = _("%(domain_name)s: %(change_count)d checks changed")
    subject_one = _("%(domain_name)s: one check changed")
    preheader = _("%(domain_name)s is now %(tier)s tier.")

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
                penalty=1,
                status=DomainCheck.Status.COMPLETE,
            ),
        )
        kwargs.setdefault(
            "changes",
            [
                {
                    "check_key": "spf",
                    "check_label": "SPF",
                    "subcheck_label": "SPF record",
                    "previous_status": "pass",
                    "current_status": "fail",
                },
                {
                    "check_key": "dmarc",
                    "check_label": "DMARC",
                    "subcheck_label": "DMARC record",
                    "previous_status": "fail",
                    "current_status": "pass",
                },
            ],
        )
        return super().render_preview(
            request, context=context, language=language, **kwargs
        )

    def get_context_data(self) -> dict[str, typing.Any]:
        any_broken = any(change["current_status"] == "fail" for change in self.changes)
        return super().get_context_data() | {
            "domain": self.domain,
            "domain_name": self.domain.name,
            "changes": self.changes,
            "change_count": len(self.changes),
            "tier": self.domain_check.tier,
            "tier_variant": self.domain_check.tier_variant,
            "headline": (
                _("%(domain)s needs a look.") % {"domain": self.domain.name}
                if any_broken
                else _("%(domain)s is looking better.") % {"domain": self.domain.name}
            ),
            "verdict": (
                _("The score is now %(tier)s tier.") % {"tier": self.domain_check.tier}
            ),
            "detail_url": self.domain.get_absolute_url(),
        }

    def get_subject(self, **context) -> str:
        match context["change_count"]:
            case 1:
                return self.subject_one % context
            case _:
                return super().get_subject(**context)
