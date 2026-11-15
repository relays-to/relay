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

    PADDING: typing.ClassVar[int] = 96
    TEXT_WIDTH: typing.ClassVar[int] = 600
    # The card is 630 tall. 630 / 1.618 lands on 389, which is the domain's
    # baseline, so the type block sits above the middle rather than on it.
    DOMAIN_BASELINE: typing.ClassVar[int] = 389
    HEADER_BASELINE: typing.ClassVar[int] = 150
    STATUS_BASELINE: typing.ClassVar[int] = 452
    TIER_CENTER: typing.ClassVar[tuple[int, int]] = (919, 300)
    TIER_RADIUS: typing.ClassVar[int] = 185
    RING_SEGMENTS: typing.ClassVar[int] = 96
    RING_WIDTH: typing.ClassVar[int] = 10
    RING_SCALE: typing.ClassVar[int] = 4

    def tier_bed(self, color: RGB) -> RGB:
        """Return a near-black cast of the metal for the face of the medal."""
        return tuple(round(channel * 0.2 + 8) for channel in color)

    def tier_color(self) -> RGB:
        """Return the tier's colour, or the ink while the check runs."""
        if self.check.status != self.check.Status.COMPLETE:
            return self.INK
        return self.check.tier.color

    def draw(self, image: Image.Image) -> None:
        draw = ImageDraw.Draw(image)
        self.draw_header(draw)
        self.draw_domain(draw)
        self.draw_status(draw)
        self.draw_tier(image, draw)

    def draw_header(self, draw) -> None:
        left = self.PADDING - 4
        wordmark = self.font("space-mono-700-italic.ttf", 58)
        draw.text(
            (left, self.HEADER_BASELINE),
            "relay",
            font=wordmark,
            fill=self.INK,
            anchor="ls",
        )
        label = self.font("fira-sans-500.ttf", 28)
        left += draw.textlength("relay", font=wordmark) + 18
        draw.text(
            (left, self.HEADER_BASELINE),
            "|",
            font=label,
            fill=(*self.INK, 110),
            anchor="ls",
        )
        left += draw.textlength("|", font=label) + 18
        draw.text(
            (left, self.HEADER_BASELINE),
            "email domain check",
            font=label,
            fill=(*self.INK, 200),
            anchor="ls",
        )

    def draw_domain(self, draw) -> None:
        name = self.check.name
        for size in range(116, 42, -2):
            candidate = self.font("fira-sans-700.ttf", size)
            if draw.textlength(name, font=candidate) <= self.TEXT_WIDTH:
                draw.text(
                    (self.PADDING - 4, self.DOMAIN_BASELINE),
                    name,
                    font=candidate,
                    fill=self.INK,
                    anchor="ls",
                )
                return
        head, _, tail = name.rpartition(".")
        if head:
            for size in range(64, 34, -2):
                candidate = self.font("fira-sans-700.ttf", size)
                if (
                    draw.textlength(f"{head}.", font=candidate) <= self.TEXT_WIDTH
                    and draw.textlength(tail, font=candidate) <= self.TEXT_WIDTH
                ):
                    draw.text(
                        (self.PADDING - 4, self.DOMAIN_BASELINE - size - 12),
                        f"{head}.",
                        font=candidate,
                        fill=self.INK,
                        anchor="ls",
                    )
                    draw.text(
                        (self.PADDING - 4, self.DOMAIN_BASELINE),
                        tail,
                        font=candidate,
                        fill=self.INK,
                        anchor="ls",
                    )
                    return
        candidate = self.font("fira-sans-700.ttf", 42)
        trimmed = name
        while (
            trimmed and draw.textlength(f"{trimmed}…", font=candidate) > self.TEXT_WIDTH
        ):
            trimmed = trimmed[:-1]
        draw.text(
            (self.PADDING - 4, self.DOMAIN_BASELINE),
            f"{trimmed}…",
            font=candidate,
            fill=self.INK,
            anchor="ls",
        )

    def draw_status(self, draw) -> None:
        draw.text(
            (self.PADDING, self.STATUS_BASELINE),
            self.check.status_line,
            font=self.font("fira-sans-500.ttf", 36),
            fill=(*self.INK, 225),
            anchor="ls",
        )

    def tier_ring(self, color: RGB) -> Image.Image:
        """Render the rim of the medal, lit from the top left."""
        diameter = 2 * self.TIER_RADIUS
        scale = self.RING_SCALE
        layer = Image.new("RGBA", (diameter * scale, diameter * scale), (0, 0, 0, 0))
        pen = ImageDraw.Draw(layer)
        bounds = (0, 0, diameter * scale - 1, diameter * scale - 1)
        medal = self.check.tier.medal
        light = tuple(round(c + (255 - c) * 0.62) for c in color)
        dark = tuple(round(c * 0.34) for c in color)
        span = 360 / self.RING_SEGMENTS
        for step in range(self.RING_SEGMENTS):
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
                width=self.RING_WIDTH * scale,
            )
        return layer.resize((diameter, diameter), Image.Resampling.LANCZOS)

    def draw_tier(self, image: Image.Image, draw) -> None:
        center_x, center_y = self.TIER_CENTER
        color = self.tier_color()
        bounds = (
            center_x - self.TIER_RADIUS,
            center_y - self.TIER_RADIUS,
            center_x + self.TIER_RADIUS,
            center_y + self.TIER_RADIUS,
        )
        draw.ellipse(bounds, fill=(*self.tier_bed(color), 240))
        image.alpha_composite(self.tier_ring(color), bounds[:2])
        letter = self.check.tier_letter
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
