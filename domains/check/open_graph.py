import dataclasses
import math
import typing

from PIL import Image, ImageDraw

from abstract.open_graph import RGB, OpenGraphImage
from domains.check.tiers import Tier
from domains.models import DomainCheck


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


@dataclasses.dataclass(kw_only=True)
class DomainCheckImage(OpenGraphImage):
    """Share card for one domain check: the domain, its issues, and its tier."""

    check: DomainCheck
    host: str = "relay.to"

    padding: typing.ClassVar[int] = 96
    text_width: typing.ClassVar[int] = 600
    # The card is 630 tall. 630 / 1.618 lands on 389, which is the domain's
    # baseline, so the type block sits above the middle rather than on it.
    domain_baseline: typing.ClassVar[int] = 389
    header_baseline: typing.ClassVar[int] = 150
    status_baseline: typing.ClassVar[int] = 452
    tier_center: typing.ClassVar[tuple[int, int]] = (919, 300)
    tier_radius: typing.ClassVar[int] = 185
    ring_segments: typing.ClassVar[int] = 96
    ring_width: typing.ClassVar[int] = 10
    ring_scale: typing.ClassVar[int] = 4

    # Platinum, gold, silver, bronze, then plain white and red.
    platinum: typing.ClassVar[RGB] = (240, 243, 248)
    gold: typing.ClassVar[RGB] = (255, 200, 45)
    silver: typing.ClassVar[RGB] = (170, 178, 192)
    bronze: typing.ClassVar[RGB] = (198, 122, 64)
    white: typing.ClassVar[RGB] = (255, 255, 255)
    red: typing.ClassVar[RGB] = (255, 88, 92)
    tier_colors: typing.ClassVar[dict[Tier, RGB]] = {
        Tier.S: platinum,
        Tier.A_PLUS: gold,
        Tier.A: gold,
        Tier.A_MINUS: gold,
        Tier.B: silver,
        Tier.B_MINUS: silver,
        Tier.C: bronze,
        Tier.C_MINUS: bronze,
        Tier.D: white,
        Tier.D_MINUS: white,
        Tier.E: red,
        Tier.E_MINUS: red,
        Tier.F: red,
    }
    medal_tiers: typing.ClassVar[frozenset[Tier]] = frozenset(
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

    def tier_bed(self, color: RGB) -> RGB:
        """Return a near-black cast of the metal for the face of the medal."""
        return tuple(round(channel * 0.2 + 8) for channel in color)

    def tier_color(self) -> RGB:
        if self.check.status != self.check.Status.COMPLETE:
            return self.ink
        return self.tier_colors[self.check.tier]

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
            (left, self.header_baseline),
            "relay",
            font=wordmark,
            fill=self.ink,
            anchor="ls",
        )
        label = self.font("fira-sans-500.ttf", 28)
        left += draw.textlength("relay", font=wordmark) + 18
        draw.text(
            (left, self.header_baseline),
            "|",
            font=label,
            fill=(*self.ink, 110),
            anchor="ls",
        )
        left += draw.textlength("|", font=label) + 18
        draw.text(
            (left, self.header_baseline),
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
                    (self.padding - 4, self.domain_baseline),
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
                        (self.padding - 4, self.domain_baseline - size - 12),
                        f"{head}.",
                        font=candidate,
                        fill=self.ink,
                        anchor="ls",
                    )
                    draw.text(
                        (self.padding - 4, self.domain_baseline),
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
            (self.padding - 4, self.domain_baseline),
            f"{trimmed}…",
            font=candidate,
            fill=self.ink,
            anchor="ls",
        )

    def draw_status(self, draw) -> None:
        draw.text(
            (self.padding, self.status_baseline),
            status_line(self.check),
            font=self.font("fira-sans-500.ttf", 36),
            fill=(*self.ink, 225),
            anchor="ls",
        )

    def tier_ring(self, color: RGB) -> Image.Image:
        """Render the rim of the medal, lit from the top left."""
        diameter = 2 * self.tier_radius
        scale = self.ring_scale
        layer = Image.new("RGBA", (diameter * scale, diameter * scale), (0, 0, 0, 0))
        pen = ImageDraw.Draw(layer)
        bounds = (0, 0, diameter * scale - 1, diameter * scale - 1)
        medal = self.check.tier in self.medal_tiers
        light = tuple(round(c + (255 - c) * 0.62) for c in color)
        dark = tuple(round(c * 0.34) for c in color)
        span = 360 / self.ring_segments
        for step in range(self.ring_segments):
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
                width=self.ring_width * scale,
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
        draw.ellipse(bounds, fill=(*self.tier_bed(color), 240))
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
