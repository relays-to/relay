from collections.abc import Iterable, Mapping

from django.db import models
from django.utils.translation import gettext_lazy as _

HALF_STEP = 1
MAX_PENALTY = 12
BLOCKING_PENALTY = 12


class Tier(models.TextChoices):
    S = "S", _("S tier")
    A_PLUS = "A+", _("A+ tier")
    A = "A", _("A tier")
    A_MINUS = "A-", _("A- tier")
    B = "B", _("B tier")
    B_MINUS = "B-", _("B- tier")
    C = "C", _("C tier")
    C_MINUS = "C-", _("C- tier")
    D = "D", _("D tier")
    D_MINUS = "D-", _("D- tier")
    E = "E", _("E tier")
    E_MINUS = "E-", _("E- tier")
    F = "F", _("F tier")


GRADES = (
    Tier.S,
    Tier.A_PLUS,
    Tier.A,
    Tier.A_MINUS,
    Tier.B,
    Tier.B_MINUS,
    Tier.C,
    Tier.C_MINUS,
    Tier.D,
    Tier.D_MINUS,
    Tier.E,
    Tier.E_MINUS,
    Tier.F,
)


def grade_for(penalty: int) -> Tier:
    return GRADES[min(penalty, MAX_PENALTY)]


def penalty_for(subchecks: Iterable[Mapping[str, str]]) -> int:
    failed = [subcheck for subcheck in subchecks if subcheck["status"] == "fail"]
    if any(subcheck.get("severity", "broken") == "blocking" for subcheck in failed):
        return BLOCKING_PENALTY
    return sum(
        2 * HALF_STEP if subcheck.get("severity", "broken") == "broken" else HALF_STEP
        for subcheck in failed
    )
