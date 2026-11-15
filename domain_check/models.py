import dataclasses
import datetime

from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from abstract.models import TimeStamped
from domains.models import validate_domain_name

from .evaluation import CHECK_HINTS, CHECK_ORDER, CHECK_SLUGS, evaluate_domain
from .tiers import Tier, grade_for, penalty_for


class DomainCheck(TimeStamped):
    CHECK_INTERVAL = datetime.timedelta(days=1)

    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        RUNNING = "running", _("running")
        COMPLETE = "complete", _("complete")
        FAILED = "failed", _("failed")

    TIER_VARIANTS = {
        Tier.S: "default",
        Tier.A_PLUS: "success",
        Tier.A: "success",
        Tier.A_MINUS: "success",
        Tier.B: "outline",
        Tier.B_MINUS: "outline",
        Tier.C: "warning",
        Tier.C_MINUS: "warning",
        Tier.D: "warning",
        Tier.D_MINUS: "warning",
        Tier.E: "destructive",
        Tier.E_MINUS: "destructive",
        Tier.F: "destructive",
    }

    name = models.CharField(
        _("domain"),
        max_length=255,
        unique=True,
        validators=[validate_domain_name],
        help_text=_("Domain name without a scheme."),
    )
    status = models.TextField(
        _("status"),
        choices=Status,
        default=Status.PENDING,
    )
    penalty = models.PositiveSmallIntegerField(
        _("penalty"),
        default=0,
        db_index=True,
        help_text=_("Half grades lost. A blocking failure pins the grade to F."),
    )
    checks = models.JSONField(
        _("checks"),
        default=list,
        help_text=_("One result per authentication check."),
    )
    checked_at = models.DateTimeField(
        _("checked at"),
        null=True,
        blank=True,
        help_text=_("When the last check ran."),
    )

    class Meta(TimeStamped.Meta):
        ordering = ["penalty", "name"]

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<DomainCheck {self.pk}>"

    def get_absolute_url(self):
        return reverse("domain_check:detail", kwargs={"name": self.name})

    @property
    def is_stale(self) -> bool:
        if self.status == self.Status.FAILED:
            return True
        if self.checked_at is None:
            return True
        reference = (
            self.modified_at
            if self.status in {self.Status.PENDING, self.Status.RUNNING}
            else self.checked_at
        )
        return timezone.now() - reference > self.CHECK_INTERVAL

    @staticmethod
    def build_check_row(check: dict) -> dict:
        subchecks = [
            {"severity": "broken"} | subcheck for subcheck in check.get("subchecks", [])
        ]
        return check | {
            "hint": CHECK_HINTS.get(check["key"], ""),
            "slug": CHECK_SLUGS.get(check["key"]),
            "subchecks": subchecks,
            "issue_count": sum(
                subcheck["status"] not in {"pass", "skip"} for subcheck in subchecks
            ),
        }

    @property
    def check_rows(self) -> list[dict]:
        return [
            self.build_check_row(check)
            for check in self.checks
            if check["key"] in CHECK_ORDER
        ]

    @property
    def issue_count(self) -> int:
        return sum(row["issue_count"] for row in self.check_rows)

    @property
    def tier(self) -> Tier:
        return grade_for(self.penalty)

    @property
    def tier_variant(self) -> str:
        return self.TIER_VARIANTS[self.tier]

    def evaluate(self):
        results = sorted(
            evaluate_domain(self.name),
            key=lambda result: CHECK_ORDER.index(result.key),
        )
        self.checks = [
            dataclasses.asdict(result) | {"status": result.status} for result in results
        ]
        self.penalty = penalty_for(
            subcheck for check in self.checks for subcheck in check.get("subchecks", [])
        )
        self.status = self.Status.COMPLETE
        self.checked_at = timezone.now()
        update_fields = (
            ["checks", "penalty", "status", "checked_at"] if self.pk else None
        )
        self.save(update_fields=update_fields)
