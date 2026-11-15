import dataclasses
import typing

from abstract.open_graph import OpenGraphImage
from domains.models import DomainCheck

PADDING = 72
TEXT_WIDTH = 660


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
    """Share card for one domain check: the domain, its issues, and its grade."""

    check: DomainCheck
    host: str = "relay.to"

    padding: typing.ClassVar[int] = PADDING
    text_width: typing.ClassVar[int] = TEXT_WIDTH
    tier_center: typing.ClassVar[tuple[int, int]] = (968, 300)
    tier_radius: typing.ClassVar[int] = 128

    def draw(self, draw) -> None:
        self.draw_wordmark(draw)
        self.draw_pill(draw, "DOMAIN CHECK")
        self.draw_domain(draw)
        self.draw_status(draw)
        self.draw_tier(draw)
        self.draw_footer(draw)

    def draw_wordmark(self, draw) -> None:
        draw.text(
            (self.padding - 4, self.padding - 12),
            "relay",
            font=self.font("space-mono-700-italic.ttf", 58),
            fill=self.ink,
        )

    def draw_pill(self, draw, label: str) -> None:
        label_font = self.font("fira-sans-500.ttf", 24)
        width = draw.textlength(label, font=label_font)
        left = self.width - self.padding - width - 52
        draw.rounded_rectangle(
            (left, self.padding - 6, self.width - self.padding, self.padding + 46),
            radius=26,
            outline=(*self.ink, 90),
            width=2,
            fill=(*self.ink, 18),
        )
        draw.text(
            (left + 26, self.padding + 6), label, font=label_font, fill=(*self.ink, 230)
        )

    def draw_domain(self, draw) -> None:
        name = self.check.name
        for size in range(108, 42, -2):
            candidate = self.font("fira-sans-700.ttf", size)
            if draw.textlength(name, font=candidate) <= self.text_width:
                draw.text((self.padding - 4, 268), name, font=candidate, fill=self.ink)
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
                        (self.padding - 4, 248),
                        f"{head}.",
                        font=candidate,
                        fill=self.ink,
                    )
                    draw.text(
                        (self.padding - 4, 248 + size + 12),
                        tail,
                        font=candidate,
                        fill=self.ink,
                    )
                    return
        candidate = self.font("fira-sans-700.ttf", 42)
        trimmed = name
        while (
            trimmed and draw.textlength(f"{trimmed}…", font=candidate) > self.text_width
        ):
            trimmed = trimmed[:-1]
        draw.text((self.padding - 4, 268), f"{trimmed}…", font=candidate, fill=self.ink)

    def draw_status(self, draw) -> None:
        draw.text(
            (self.padding, 440),
            status_line(self.check),
            font=self.font("fira-sans-500.ttf", 38),
            fill=(*self.ink, 225),
        )

    def draw_tier(self, draw) -> None:
        center_x, center_y = self.tier_center
        draw.ellipse(
            (
                center_x - self.tier_radius,
                center_y - self.tier_radius,
                center_x + self.tier_radius,
                center_y + self.tier_radius,
            ),
            fill=(*self.ink, 24),
            outline=(*self.ink, 72),
            width=3,
        )
        letter = tier_letter(self.check)
        draw.text(
            (center_x, center_y - 6),
            letter,
            font=self.font("fira-sans-700.ttf", 168 if len(letter) == 1 else 120),
            fill=self.ink,
            anchor="mm",
        )
        draw.text(
            (center_x, center_y + self.tier_radius + 44),
            "GRADE",
            font=self.font("fira-sans-500.ttf", 24),
            fill=(*self.ink, 170),
            anchor="mm",
        )

    def draw_footer(self, draw) -> None:
        draw.line(
            (self.padding, 540, self.width - self.padding, 540),
            fill=(*self.ink, 60),
            width=2,
        )
        draw.text(
            (self.padding, 566),
            f"{self.host}/domain-check",
            font=self.font("fira-sans-500.ttf", 26),
            fill=(*self.ink, 185),
        )
        draw.text(
            (self.width - self.padding, 566),
            "no signup required",
            font=self.font("fira-sans-500.ttf", 26),
            fill=(*self.ink, 185),
            anchor="ra",
        )
