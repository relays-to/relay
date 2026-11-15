import dataclasses
import typing

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


# Olympic medals: gold, silver, bronze, then a grey field and red for the
# tiers that mean mail is broken.
GOLD = (255, 205, 60)
SILVER = (201, 207, 218)
BRONZE = (214, 138, 74)
GREY = (154, 160, 173)
RED = (255, 100, 103)

TIER_COLORS = {
    Tier.S: GOLD,
    Tier.A_PLUS: SILVER,
    Tier.A: SILVER,
    Tier.A_MINUS: SILVER,
    Tier.B: BRONZE,
    Tier.B_MINUS: BRONZE,
    Tier.C: GREY,
    Tier.C_MINUS: GREY,
    Tier.D: GREY,
    Tier.D_MINUS: GREY,
    Tier.E: RED,
    Tier.E_MINUS: RED,
    Tier.F: RED,
}


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

    def draw(self, draw) -> None:
        self.draw_header(draw)
        self.draw_domain(draw)
        self.draw_status(draw)
        self.draw_tier(draw)

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

    def draw_tier(self, draw) -> None:
        center_x, center_y = self.tier_center
        color = self.tier_color()
        bounds = (
            center_x - self.tier_radius,
            center_y - self.tier_radius,
            center_x + self.tier_radius,
            center_y + self.tier_radius,
        )
        draw.ellipse(bounds, fill=(*self.tier_disc, 235))
        draw.ellipse(bounds, outline=color, width=4)
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
