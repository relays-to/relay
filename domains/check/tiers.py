import enum
import typing

from django.utils.translation import gettext_lazy as _


class Tier(enum.StrEnum):
    S = "S", _("S tier"), "default", (240, 243, 248), True
    A_PLUS = "A+", _("A+ tier"), "success", (255, 200, 45), True
    A = "A", _("A tier"), "success", (255, 200, 45), True
    A_MINUS = "A-", _("A- tier"), "success", (255, 200, 45), True
    B = "B", _("B tier"), "outline", (170, 178, 192), True
    B_MINUS = "B-", _("B- tier"), "outline", (170, 178, 192), True
    C = "C", _("C tier"), "warning", (198, 122, 64), True
    C_MINUS = "C-", _("C- tier"), "warning", (198, 122, 64), True
    D = "D", _("D tier"), "warning", (255, 255, 255), False
    D_MINUS = "D-", _("D- tier"), "warning", (255, 255, 255), False
    E = "E", _("E tier"), "destructive", (255, 88, 92), False
    E_MINUS = "E-", _("E- tier"), "destructive", (255, 88, 92), False
    F = "F", _("F tier"), "destructive", (255, 88, 92), False

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
