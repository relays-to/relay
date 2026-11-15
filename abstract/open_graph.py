import dataclasses
import datetime
import io
import pathlib
import typing

from django.core.cache import cache
from PIL import Image, ImageDraw, ImageFilter, ImageFont

type RGB = tuple[int, int, int]


@dataclasses.dataclass(kw_only=True)
class OpenGraphImage:
    """Render a share card on relay's brand background."""

    cache_key: str
    cache_ttl: datetime.timedelta

    width: typing.ClassVar[int] = 1200
    height: typing.ClassVar[int] = 630
    background_start: typing.ClassVar[RGB] = (105, 0, 209)
    background_end: typing.ClassVar[RGB] = (26, 0, 64)
    glow_color: typing.ClassVar[RGB] = (194, 37, 245)
    ink: typing.ClassVar[RGB] = (255, 255, 255)
    fonts_dir: typing.ClassVar[pathlib.Path] = pathlib.Path(__file__).with_name("fonts")

    def font(self, name: str, size: int) -> ImageFont.FreeTypeFont:
        return ImageFont.truetype(str(self.fonts_dir / name), size)

    def fit(
        self, draw, text: str, name: str, start: int, minimum: int, limit: int
    ) -> ImageFont.FreeTypeFont:
        size = start
        while (
            size > minimum and draw.textlength(text, font=self.font(name, size)) > limit
        ):
            size -= 2
        return self.font(name, size)

    def background(self) -> Image.Image:
        gradient = Image.new("RGB", (2, 2))
        gradient.putpixel((0, 0), self.background_start)
        gradient.putpixel((1, 0), self.background_end)
        gradient.putpixel((0, 1), self.background_start)
        gradient.putpixel((1, 1), self.background_end)
        image = gradient.resize(
            (self.width, self.height), Image.Resampling.BILINEAR
        ).convert("RGBA")

        mask = Image.new("L", (self.width, self.height), 0)
        ImageDraw.Draw(mask).ellipse(
            (self.width - 620, -300, self.width + 280, 480), fill=150
        )
        mask = mask.filter(ImageFilter.GaussianBlur(150))
        image.paste(
            Image.new("RGBA", (self.width, self.height), (*self.glow_color, 255)),
            (0, 0),
            mask,
        )
        return image

    def draw(self, draw: ImageDraw.ImageDraw) -> None:
        raise NotImplementedError

    def render(self) -> bytes:
        if not (payload := cache.get(self.cache_key)):
            image = self.background()
            overlay = Image.new("RGBA", (self.width, self.height), (0, 0, 0, 0))
            self.draw(ImageDraw.Draw(overlay))
            image = Image.alpha_composite(image, overlay)
            buffer = io.BytesIO()
            image.convert("RGB").save(buffer, format="PNG", optimize=True)
            payload = buffer.getvalue()
            cache.set(self.cache_key, payload, timeout=self.cache_ttl.total_seconds())
        return payload
