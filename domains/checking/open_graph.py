import dataclasses
import math
import typing

from PIL import Image, ImageDraw

from abstract.open_graph import RGB, OpenGraphImage
from domains.checking.tiers import Tier
from domains.models import DomainCheck

PADDING = 96
TEXT_WIDTH = 600
# The card is 630 tall. 630 / 1.618 lands on 389, which is the domain's
# baseline, so the type block sits above the middle rather than on it.
DOMAIN_BASELINE = 389
HEADER_BASELINE = 150
STATUS_BASELINE = 452


def issue_phrase(count: int) -> str:
    if count == 0:
        return "All checks pass"
    suffix = "s" if count != 1 else ""
    verb = "needs" if count == 1 else "need"
    return f"{count} issue{suffix} {verb} attention"


def status_line(check) -> str:
    match check.status:
        case check.Status.COMPLETE:
            return issue_phrase(check.issue_count)
        case check.Status.FAILED:
            return "The last check failed"
        case _:
            return "Check in progress"


def tier_letter(check) -> str:
    return str(check.tier) if check.status == check.Status.COMPLETE else "\u2013"


# Platinum, gold, silver, bronze, then plain white and red.
PLATINUM = (240, 243, 248)
GOLD = (255, 200, 45)
SILVER = (170, 178, 192)
BRONZE = (198, 122, 64)
RED = (255, 88, 92)

TIER_COLORS = {
    Tier.S: PLATINUM,
    Tier.A_PLUS: GOLD,
    Tier.A: GOLD,
    Tier.A_MINUS: GOLD,
    Tier.B: SILVER,
    Tier.B_MINUS: SILVER,
    Tier.C: BRONZE,
    Tier.C_MINUS: BRONZE,
    Tier.D: (255, 255, 255),
    Tier.D_MINUS: (255, 255, 255),
    Tier.E: RED,
    Tier.E_MINUS: RED,
    Tier.F: RED,
}

MEDAL_TIERS = frozenset(
    {
        Tier.S,
        Tier.A_PLUS,
        Tier.A,
        Tier.A_MINUS,
        Tier.B,
        Tier.B_MINUS,
        Tier.C,
        Tier.C_MINUS,
    }
)
RING_SEGMENTS = 96
RING_WIDTH = 10
RING_SCALE = 4


@dataclasses.dataclass(kw_only=True)
class DomainCheckImage(OpenGraphImage):
    """Share card for one domain check: the domain, its issues, and its tier."""

    check: DomainCheck
    host: str = "relay.to"

    padding: typing.ClassVar[int] = PADDING
    text_width: typing.ClassVar[int] = TEXT_WIDTH
    tier_center: typing.ClassVar[tuple[int, int]] = (919, 300)
    tier_radius: typing.ClassVar[int] = 185
    # A dark bed so the tier colour survives the bright end of the gradient.
    tier_disc: typing.ClassVar[RGB] = (26, 6, 60)

    def tier_color(self) -> RGB:
        if self.check.status != self.check.Status.COMPLETE:
            return self.ink
        return TIER_COLORS[self.check.tier]

    def draw(self, image: Image.Image) -> None:
        draw = ImageDraw.Draw(image)
        self.draw_header(draw)
        self.draw_domain(draw)
        self.draw_status(draw)
        self.draw_tier(image, draw)

    def draw_header(self, draw) -> None:
        left = self.padding - 4
        wordmark = self.font("space-mono-700-italic.ttf", 58)
        draw.text(
            (left, HEADER_BASELINE), "relay", font=wordmark, fill=self.ink, anchor="ls"
        )
        label = self.font("fira-sans-500.ttf", 28)
        left += draw.textlength("relay", font=wordmark) + 18
        draw.text(
            (left, HEADER_BASELINE),
            "|",
            font=label,
            fill=(*self.ink, 110),
            anchor="ls",
        )
        left += draw.textlength("|", font=label) + 18
        draw.text(
            (left, HEADER_BASELINE),
            "email domain check",
            font=label,
            fill=(*self.ink, 200),
            anchor="ls",
        )

    def draw_domain(self, draw) -> None:
        name = self.check.name
        for size in range(116, 42, -2):
            candidate = self.font("fira-sans-700.ttf", size)
            if draw.textlength(name, font=candidate) <= self.text_width:
                draw.text(
                    (self.padding - 4, DOMAIN_BASELINE),
                    name,
                    font=candidate,
                    fill=self.ink,
                    anchor="ls",
                )
                return
        head, _, tail = name.rpartition(".")
        if head:
            for size in range(64, 34, -2):
                candidate = self.font("fira-sans-700.ttf", size)
                if (
                    draw.textlength(f"{head}.", font=candidate) <= self.text_width
                    and draw.textlength(tail, font=candidate) <= self.text_width
                ):
                    draw.text(
                        (self.padding - 4, DOMAIN_BASELINE - size - 12),
                        f"{head}.",
                        font=candidate,
                        fill=self.ink,
                        anchor="ls",
                    )
                    draw.text(
                        (self.padding - 4, DOMAIN_BASELINE),
                        tail,
                        font=candidate,
                        fill=self.ink,
                        anchor="ls",
                    )
                    return
        candidate = self.font("fira-sans-700.ttf", 42)
        trimmed = name
        while (
            trimmed and draw.textlength(f"{trimmed}…", font=candidate) > self.text_width
        ):
            trimmed = trimmed[:-1]
        draw.text(
            (self.padding - 4, DOMAIN_BASELINE),
            f"{trimmed}…",
            font=candidate,
            fill=self.ink,
            anchor="ls",
        )

    def draw_status(self, draw) -> None:
        draw.text(
            (self.padding, STATUS_BASELINE),
            status_line(self.check),
            font=self.font("fira-sans-500.ttf", 36),
            fill=(*self.ink, 225),
            anchor="ls",
        )

    def tier_ring(self, color: RGB) -> Image.Image:
        """Render the rim of the medal, lit from the top left."""
        diameter = 2 * self.tier_radius
        scale = RING_SCALE
        layer = Image.new("RGBA", (diameter * scale, diameter * scale), (0, 0, 0, 0))
        pen = ImageDraw.Draw(layer)
        bounds = (0, 0, diameter * scale - 1, diameter * scale - 1)
        medal = self.check.tier in MEDAL_TIERS
        light = tuple(round(c + (255 - c) * 0.62) for c in color)
        dark = tuple(round(c * 0.34) for c in color)
        span = 360 / RING_SEGMENTS
        for step in range(RING_SEGMENTS):
            start = step * span
            if medal:
                shine = (math.cos(math.radians(start + span / 2 - 225)) + 1) / 2
                fill = tuple(
                    round(shadow + (bright - shadow) * shine)
                    for shadow, bright in zip(dark, light)
                )
            else:
                fill = color
            pen.arc(
                bounds,
                start,
                start + span + 0.5,
                fill=(*fill, 255),
                width=RING_WIDTH * scale,
            )
        return layer.resize((diameter, diameter), Image.Resampling.LANCZOS)

    def draw_tier(self, image: Image.Image, draw) -> None:
        center_x, center_y = self.tier_center
        color = self.tier_color()
        bounds = (
            center_x - self.tier_radius,
            center_y - self.tier_radius,
            center_x + self.tier_radius,
            center_y + self.tier_radius,
        )
        draw.ellipse(bounds, fill=(*self.tier_disc, 235))
        image.alpha_composite(self.tier_ring(color), bounds[:2])
        letter = tier_letter(self.check)
        font = self.font("fira-sans-700.ttf", 300 if len(letter) == 1 else 220)
        mask, (offset_x, offset_y) = font.getmask2(letter, mode="L")
        if (ink := mask.getbbox()) is not None:
            # Center the painted pixels, not the em box, which carries the side
            # bearings and descender space the letter never fills.
            left, top = offset_x + ink[0], offset_y + ink[1]
            right, bottom = offset_x + ink[2], offset_y + ink[3]
            draw.text(
                (center_x - (left + right) / 2, center_y - (top + bottom) / 2),
                letter,
                font=font,
                fill=color,
            )
