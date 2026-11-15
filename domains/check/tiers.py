import enum
import typing
from collections.abc import Iterable, Mapping

from django.utils.translation import gettext_lazy as _

HALF_STEP = 1
MAX_PENALTY = 12
BLOCKING_PENALTY = 12

PLATINUM = (240, 243, 248)
GOLD = (255, 200, 45)
SILVER = (170, 178, 192)
BRONZE = (198, 122, 64)
WHITE = (255, 255, 255)
RED = (255, 88, 92)


class Tier(enum.StrEnum):
    """A grade with the variant and the colour its interfaces render."""

    S = "S", _("S tier"), "default", PLATINUM, True
    A_PLUS = "A+", _("A+ tier"), "success", GOLD, True
    A = "A", _("A tier"), "success", GOLD, True
    A_MINUS = "A-", _("A- tier"), "success", GOLD, True
    B = "B", _("B tier"), "outline", SILVER, True
    B_MINUS = "B-", _("B- tier"), "outline", SILVER, True
    C = "C", _("C tier"), "warning", BRONZE, True
    C_MINUS = "C-", _("C- tier"), "warning", BRONZE, True
    D = "D", _("D tier"), "warning", WHITE, False
    D_MINUS = "D-", _("D- tier"), "warning", WHITE, False
    E = "E", _("E tier"), "destructive", RED, False
    E_MINUS = "E-", _("E- tier"), "destructive", RED, False
    F = "F", _("F tier"), "destructive", RED, False

    def __new__(
        cls,
        value: str,
        label: str,
        variant: str,
        color: tuple[int, int, int],
        medal: bool,
    ) -> typing.Self:
        tier = str.__new__(cls, value)
        tier._value_ = value
        tier.label = label
        # The basecoat variant the badges and rows use.
        tier.variant = variant
        # The colour the share card draws the ring and the glyph in.
        tier.color = color
        # Whether the card strikes that colour as a medal.
        tier.medal = medal
        return tier


def penalty_for(subchecks: Iterable[Mapping[str, str]]) -> int:
    failed = [subcheck for subcheck in subchecks if subcheck["status"] == "fail"]
    if any(subcheck.get("severity", "broken") == "blocking" for subcheck in failed):
        return BLOCKING_PENALTY
    return sum(
        2 * HALF_STEP if subcheck.get("severity", "broken") == "broken" else HALF_STEP
        for subcheck in failed
    )
