import dataclasses
import datetime as dt
import io
import pathlib
import typing

from django.core import signing
from django.core.cache import cache
from PIL import Image, ImageDraw, ImageFont

type RGB = tuple[int, int, int]

signer = signing.Signer(salt="open-graph")


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

    def draw_ink_left(
        self,
        image: Image.Image,
        x: float,
        baseline: float,
        text: str,
        font: ImageFont.FreeTypeFont,
        fill: tuple[int, ...],
    ) -> float:
        """Composite text with its leftmost ink on `x` and return its right edge."""
        layer = Image.new("RGBA", (self.WIDTH_PX, self.HEIGHT_PX), (0, 0, 0, 0))
        ImageDraw.Draw(layer).text(
            (0, baseline), text, font=font, fill=fill, anchor="ls"
        )
        left, _top, right, _bottom = layer.getbbox()
        image.alpha_composite(layer, (round(x - left), 0))
        return x + right - left

    def draw_wordmark(self, image: Image.Image, label: str) -> None:
        """Render the relay wordmark with a descriptor beside it."""
        baseline = self.HEADER_BASELINE_PX
        wordmark_font = self.font("space-mono-700-italic.ttf", 58)
        label_font = self.font("fira-sans-500.ttf", 28)
        right = self.draw_ink_left(
            image, self.PADDING_PX, baseline, "relay", wordmark_font, self.INK
        )
        draw = ImageDraw.Draw(image)
        divider = right + 20
        label_box = draw.textbbox((0, baseline), label, font=label_font, anchor="ls")
        x_height = draw.textbbox((0, baseline), "rea", font=wordmark_font, anchor="ls")
        label_baseline = (
            baseline
            + (x_height[1] + x_height[3]) / 2
            - (label_box[1] + label_box[3]) / 2
        )
        label_box = draw.textbbox(
            (0, label_baseline), label, font=label_font, anchor="ls"
        )
        draw.rounded_rectangle(
            (divider, label_box[1], divider + 3, label_box[3]),
            radius=1.5,
            fill=(*self.INK, 110),
        )
        self.draw_ink_left(
            image,
            divider + 20 + 3,
            label_baseline,
            label,
            label_font,
            (*self.INK, 200),
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
        self.draw_centered(
            image,
            self.WORDMARK,
            self.font("space-mono-700-italic.ttf", self.WORDMARK_SIZE_PX),
            self.WORDMARK_BASELINE_PX,
        )
        self.draw_centered(
            image,
            self.TAGLINE,
            self.font("fira-sans-700.ttf", self.TAGLINE_SIZE_PX),
            self.TAGLINE_BASELINE_PX,
        )

    def draw_centered(
        self,
        image: Image.Image,
        text: str,
        font: ImageFont.FreeTypeFont,
        baseline: float,
    ) -> None:
        layer = Image.new("RGBA", (self.WIDTH_PX, self.HEIGHT_PX), (0, 0, 0, 0))
        ImageDraw.Draw(layer).text(
            (0, baseline), text, font=font, fill=self.INK, anchor="ls"
        )
        left, _top, right, _bottom = layer.getbbox()
        image.alpha_composite(
            layer, (round((self.WIDTH_PX - (right - left)) / 2 - left), 0)
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
        self.draw_wordmark(image, "communication as a service")
        self.draw_title(image)

    def draw_title(self, image: Image.Image) -> None:
        draw = ImageDraw.Draw(image)
        font, lines = self.fit_title(draw)
        spacing = round(font.size * self.TITLE_SPACING_RATIO)
        text = "\n".join(lines)
        layer = Image.new("RGBA", (self.WIDTH_PX, self.HEIGHT_PX), (0, 0, 0, 0))
        ImageDraw.Draw(layer).multiline_text(
            (0, 0), text, font=font, fill=self.INK, spacing=spacing
        )
        left, top, _right, bottom = layer.getbbox()
        x = round(self.PADDING_PX - left)
        y = round(
            (self.TITLE_TOP_PX + self.TITLE_BOTTOM_PX) / 2 - (bottom - top) / 2 - top
        )
        image.alpha_composite(layer, (x, y))

    def fit_title(
        self, draw: ImageDraw.ImageDraw
    ) -> tuple[ImageFont.FreeTypeFont, list[str]]:
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
                while draw.textlength(word[:cut], font=font) > self.TITLE_WIDTH_PX:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
        return lines

    def ellipsize(
        self, draw: ImageDraw.ImageDraw, font: ImageFont.FreeTypeFont, line: str
    ) -> str:
        while draw.textlength(f"{line.rstrip()}…", font=font) > self.TITLE_WIDTH_PX:
            line = line[:-1]
        return f"{line.rstrip()}…"
