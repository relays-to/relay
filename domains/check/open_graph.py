import dataclasses
import math
import typing

from PIL import Image, ImageDraw

from abstract.open_graph import RGB, OpenGraphImage
from domains.models import DomainCheck


@dataclasses.dataclass(kw_only=True)
class DomainCheckImage(OpenGraphImage):
    """Share card for one domain check: the domain, its issues, and its tier."""

    check: DomainCheck
    host: str = "relay.to"

    TEXT_WIDTH_PX: typing.ClassVar[int] = 600
    # The card is 630 tall. 630 / 1.618 lands on 389, which is the domain's
    # baseline, so the type block sits above the middle rather than on it.
    DOMAIN_BASELINE_PX: typing.ClassVar[int] = 389
    STATUS_BASELINE_PX: typing.ClassVar[int] = 452
    TIER_CENTER_PX: typing.ClassVar[tuple[int, int]] = (919, 300)
    TIER_RADIUS_PX: typing.ClassVar[int] = 185
    RING_SEGMENTS: typing.ClassVar[int] = 96
    RING_SCALE: typing.ClassVar[int] = 4

    def tier_color(self) -> RGB:
        """Return the tier's colour, or the ink while the check runs."""
        if self.check.status != self.check.Status.COMPLETE:
            return self.INK
        return self.check.tier.color

    def tier_accent(self) -> RGB | None:
        """Return the tier's second colour, or nothing while the check runs."""
        if self.check.status != self.check.Status.COMPLETE:
            return None
        return self.check.tier.accent

    def draw(self, image: Image.Image) -> None:
        self.draw_header(image)
        self.draw_domain(image)
        self.draw_status(image)
        self.draw_tier(image, ImageDraw.Draw(image))

    def draw_header(self, image) -> None:
        self.draw_wordmark(image, "email domain check")

    def draw_domain(self, image) -> None:
        draw = ImageDraw.Draw(image)
        name = self.check.name
        for size in range(116, 42, -2):
            candidate = self.font("fira-sans-700.ttf", size)
            if draw.textlength(name, font=candidate) <= self.TEXT_WIDTH_PX:
                self.draw_ink_left(
                    image,
                    self.PADDING_PX,
                    self.DOMAIN_BASELINE_PX,
                    name,
                    candidate,
                    self.INK,
                )
                return
        head, _, tail = name.rpartition(".")
        if head:
            for size in range(64, 34, -2):
                candidate = self.font("fira-sans-700.ttf", size)
                if (
                    draw.textlength(f"{head}.", font=candidate) <= self.TEXT_WIDTH_PX
                    and draw.textlength(tail, font=candidate) <= self.TEXT_WIDTH_PX
                ):
                    self.draw_ink_left(
                        image,
                        self.PADDING_PX,
                        self.DOMAIN_BASELINE_PX - size - 12,
                        f"{head}.",
                        candidate,
                        self.INK,
                    )
                    self.draw_ink_left(
                        image,
                        self.PADDING_PX,
                        self.DOMAIN_BASELINE_PX,
                        tail,
                        candidate,
                        self.INK,
                    )
                    return
        candidate = self.font("fira-sans-700.ttf", 42)
        trimmed = name
        while (
            trimmed
            and draw.textlength(f"{trimmed}…", font=candidate) > self.TEXT_WIDTH_PX
        ):
            trimmed = trimmed[:-1]
        self.draw_ink_left(
            image,
            self.PADDING_PX,
            self.DOMAIN_BASELINE_PX,
            f"{trimmed}…",
            candidate,
            self.INK,
        )

    def draw_status(self, image) -> None:
        self.draw_ink_left(
            image,
            self.PADDING_PX,
            self.STATUS_BASELINE_PX,
            self.check.status_line,
            self.font("fira-sans-500.ttf", 36),
            (*self.INK, 225),
        )

    def tier_ring(self, color: RGB) -> Image.Image:
        """Render the rim of the medal, lit from the top left."""
        diameter = 2 * self.TIER_RADIUS_PX
        scale = self.RING_SCALE
        layer = Image.new("RGBA", (diameter * scale, diameter * scale), (0, 0, 0, 0))
        pen = ImageDraw.Draw(layer)
        bounds = (0, 0, diameter * scale - 1, diameter * scale - 1)
        tier = self.check.tier
        accent = self.tier_accent()
        light = tuple(round(c + (255 - c) * 0.62) for c in color)
        dark = tuple(round(c * 0.34) for c in color)
        span = 360 / self.RING_SEGMENTS
        for step in range(self.RING_SEGMENTS):
            start = step * span
            shine = (math.cos(math.radians(start + span / 2 - 225)) + 1) / 2
            if accent:
                # A two-tone medal: the accent owns the lit side, the base
                # colour the shaded side.
                fill = tuple(
                    round(base + (bright - base) * shine)
                    for base, bright in zip(color, accent)
                )
            elif tier.medal:
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
                width=tier.ring_width * scale,
            )
        return layer.resize((diameter, diameter), Image.Resampling.LANCZOS)

    def draw_tier(self, image: Image.Image, draw) -> None:
        center_x, center_y = self.TIER_CENTER_PX
        color = self.tier_color()
        bounds = (
            center_x - self.TIER_RADIUS_PX,
            center_y - self.TIER_RADIUS_PX,
            center_x + self.TIER_RADIUS_PX,
            center_y + self.TIER_RADIUS_PX,
        )
        bed = tuple(round(channel * 0.2 + 8) for channel in color)
        draw.ellipse(bounds, fill=(*bed, 240))
        image.alpha_composite(self.tier_ring(color), bounds[:2])
        letter = self.check.tier_letter
        font = self.font("playfair-display-700.ttf", 300 if len(letter) == 1 else 220)
        mask, (offset_x, offset_y) = font.getmask2(letter, mode="L")
        ink = mask.getbbox()
        # Center the painted pixels, not the em box, which carries the side
        # bearings and descender space the letter never fills.
        left, top = offset_x + ink[0], offset_y + ink[1]
        right, bottom = offset_x + ink[2], offset_y + ink[3]
        draw.text(
            (center_x - (left + right) / 2, center_y - (top + bottom) / 2),
            letter,
            font=font,
            fill=self.tier_accent() or color,
        )
