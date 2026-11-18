import dataclasses
import datetime as dt
import io
import pathlib
import typing

from django.core.cache import cache
from PIL import Image, ImageDraw, ImageFont

type RGB = tuple[int, int, int]


@dataclasses.dataclass(kw_only=True)
class OpenGraphImage:
    """Render a share card on relay's brand background."""

    cache_key: str
    cache_ttl: dt.timedelta

    WIDTH_PX: typing.ClassVar[int] = 1200
    HEIGHT_PX: typing.ClassVar[int] = 630
    # Navy top left, teal top right, a blue-violet bottom right, and a deeper
    # navy bottom left. The right edge reaches the blue-violet about a third
    # down.
    BACKGROUND_POINTS: typing.ClassVar[tuple[RGB, RGB, RGB, RGB]] = (
        (30, 68, 138),
        (20, 184, 166),
        (49, 41, 149),
        (20, 44, 88),
    )
    INK: typing.ClassVar[RGB] = (255, 255, 255)
    FONTS_DIR: typing.ClassVar[pathlib.Path] = pathlib.Path(__file__).with_name("fonts")
    PADDING_PX: typing.ClassVar[int] = 96
    HEADER_BASELINE_PX: typing.ClassVar[int] = 150

    def font(self, name: str, size: int) -> ImageFont.FreeTypeFont:
        return ImageFont.truetype(str(self.FONTS_DIR / name), size)

    def draw_wordmark(self, draw: ImageDraw.ImageDraw, label: str) -> None:
        """Draw the relay wordmark and a label on the same baseline."""
        left = self.PADDING_PX - 4
        wordmark = self.font("space-mono-700-italic.ttf", 58)
        draw.text(
            (left, self.HEADER_BASELINE_PX),
            "relay",
            font=wordmark,
            fill=self.INK,
            anchor="ls",
        )
        label_font = self.font("fira-sans-500.ttf", 28)
        left += draw.textlength("relay", font=wordmark) + 18
        draw.text(
            (left, self.HEADER_BASELINE_PX),
            "|",
            font=label_font,
            fill=(*self.INK, 110),
            anchor="ls",
        )
        left += draw.textlength("|", font=label_font) + 18
        draw.text(
            (left, self.HEADER_BASELINE_PX),
            label,
            font=label_font,
            fill=(*self.INK, 200),
            anchor="ls",
        )

    def background(self) -> Image.Image:
        top_left, top_right, bottom_right, bottom_left = self.BACKGROUND_POINTS
        # A tenth of the canvas holds the same blend, and upscaling keeps it smooth.
        small = Image.new("RGB", (self.WIDTH_PX // 10, self.HEIGHT_PX // 10))
        # The right edge reaches blue-violet about a third down, so the teal stays
        # in the corner.
        ends = [
            (
                tuple(a * (1 - down) + b * down for a, b in zip(top_left, bottom_left)),
                tuple(
                    a * (1 - down) ** 2 + b * (1 - (1 - down) ** 2)
                    for a, b in zip(top_right, bottom_right)
                ),
            )
            for down in (y / (small.height - 1) for y in range(small.height))
        ]
        small.putdata(
            [
                tuple(round(a + (b - a) * across) for a, b in zip(left, right))
                for left, right in ends
                for across in (x / (small.width - 1) for x in range(small.width))
            ]
        )
        return small.resize((self.WIDTH_PX, self.HEIGHT_PX)).convert("RGBA")

    def draw(self, image: Image.Image) -> None:
        raise NotImplementedError

    def compose(self) -> Image.Image:
        """Draw the overlay on the background and return the finished card."""
        image = self.background()
        overlay = Image.new("RGBA", (self.WIDTH_PX, self.HEIGHT_PX), (0, 0, 0, 0))
        self.draw(overlay)
        return Image.alpha_composite(image, overlay)

    def render(self) -> bytes:
        if not (payload := cache.get(self.cache_key)):
            buffer = io.BytesIO()
            self.compose().convert("RGB").save(buffer, format="PNG", optimize=True)
            payload = buffer.getvalue()
            cache.set(self.cache_key, payload, timeout=self.cache_ttl.total_seconds())
        return payload


@dataclasses.dataclass(kw_only=True)
class BrandImage(OpenGraphImage):
    """Render the relay wordmark and tagline as the default share card."""

    WORDMARK: typing.ClassVar[str] = "relay"
    WORDMARK_SIZE_PX: typing.ClassVar[int] = 170
    WORDMARK_BASELINE_PX: typing.ClassVar[int] = 345
    TAGLINE: typing.ClassVar[str] = "Communication as a Service"
    TAGLINE_SIZE_PX: typing.ClassVar[int] = 52
    TAGLINE_BASELINE_PX: typing.ClassVar[int] = 455

    def draw(self, image: Image.Image) -> None:
        draw = ImageDraw.Draw(image)
        center_x = self.WIDTH_PX / 2
        draw.text(
            (center_x, self.WORDMARK_BASELINE_PX),
            self.WORDMARK,
            font=self.font("space-mono-700-italic.ttf", self.WORDMARK_SIZE_PX),
            fill=self.INK,
            anchor="ms",
        )
        draw.text(
            (center_x, self.TAGLINE_BASELINE_PX),
            self.TAGLINE,
            font=self.font("fira-sans-700.ttf", self.TAGLINE_SIZE_PX),
            fill=self.INK,
            anchor="ms",
        )


@dataclasses.dataclass(kw_only=True)
class TitleImage(OpenGraphImage):
    """Render a page title on relay's brand background."""

    title: str

    TITLE_TOP_PX: typing.ClassVar[int] = 214
    TITLE_BOTTOM_PX: typing.ClassVar[int] = 544
    TITLE_WIDTH_PX: typing.ClassVar[int] = 1008
    TITLE_MAX_SIZE_PX: typing.ClassVar[int] = 104
    TITLE_MIN_SIZE_PX: typing.ClassVar[int] = 48
    TITLE_SIZE_STEP_PX: typing.ClassVar[int] = 4
    TITLE_MAX_LINES: typing.ClassVar[int] = 3
    TITLE_SPACING_RATIO: typing.ClassVar[float] = 0.16
    TITLE_FONT: typing.ClassVar[str] = "fira-sans-700.ttf"

    def draw(self, image: Image.Image) -> None:
        draw = ImageDraw.Draw(image)
        self.draw_wordmark(draw, "communication as a service")
        self.draw_title(draw)

    def draw_title(self, draw: ImageDraw.ImageDraw) -> None:
        font, lines = self.fit_title(draw)
        spacing = round(font.size * self.TITLE_SPACING_RATIO)
        text = "\n".join(lines)
        box = draw.multiline_textbbox((0, 0), text, font=font, spacing=spacing)
        top = (
            (self.TITLE_TOP_PX + self.TITLE_BOTTOM_PX) / 2
            - (box[3] - box[1]) / 2
            - box[1]
        )
        draw.multiline_text(
            (self.PADDING_PX - 4, top),
            text,
            font=font,
            fill=self.INK,
            spacing=spacing,
        )

    def fit_title(
        self, draw: ImageDraw.ImageDraw
    ) -> tuple[ImageFont.FreeTypeFont, list[str]]:
        """Return the largest font and the wrapped title that fit the card."""
        title = " ".join(self.title.split()) or "relay"
        for size in range(
            self.TITLE_MAX_SIZE_PX,
            self.TITLE_MIN_SIZE_PX - 1,
            -self.TITLE_SIZE_STEP_PX,
        ):
            font = self.font(self.TITLE_FONT, size)
            lines = self.wrap_title(draw, font, title)
            if len(lines) <= self.TITLE_MAX_LINES:
                return font, lines
        font = self.font(self.TITLE_FONT, self.TITLE_MIN_SIZE_PX)
        lines = self.wrap_title(draw, font, title)[: self.TITLE_MAX_LINES]
        lines[-1] = self.ellipsize(draw, font, lines[-1])
        return font, lines

    def wrap_title(
        self, draw: ImageDraw.ImageDraw, font: ImageFont.FreeTypeFont, title: str
    ) -> list[str]:
        """Wrap `title` to the card width and break words that cannot fit."""
        lines: list[str] = []
        line = ""
        for word in title.split():
            candidate = f"{line} {word}".strip()
            if draw.textlength(candidate, font=font) <= self.TITLE_WIDTH_PX:
                line = candidate
                continue
            if line:
                lines.append(line)
                line = ""
            while draw.textlength(word, font=font) > self.TITLE_WIDTH_PX:
                cut = len(word)
                while cut and (
                    draw.textlength(word[:cut], font=font) > self.TITLE_WIDTH_PX
                ):
                    cut -= 1
                cut = max(cut, 1)
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        if line:
            lines.append(line)
        return lines

    def ellipsize(
        self, draw: ImageDraw.ImageDraw, font: ImageFont.FreeTypeFont, line: str
    ) -> str:
        """Trim `line` until it and an ellipsis fit the card width."""
        while line and (
            draw.textlength(f"{line.rstrip()}…", font=font) > self.TITLE_WIDTH_PX
        ):
            line = line[:-1]
        return f"{line.rstrip()}…"
