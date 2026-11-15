import dataclasses
import datetime
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
    cache_ttl: datetime.timedelta

    width: typing.ClassVar[int] = 1200
    height: typing.ClassVar[int] = 630
    # The favicon gradient: #6200d1 to #14b8a6.
    background_start: typing.ClassVar[RGB] = (98, 0, 209)
    background_end: typing.ClassVar[RGB] = (20, 184, 166)
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
        start, end = self.background_start, self.background_end
        ramp = Image.new("RGB", (self.width, 1))
        for x in range(self.width):
            step = x / (self.width - 1)
            ramp.putpixel(
                (x, 0), tuple(round(a + (b - a) * step) for a, b in zip(start, end))
            )
        return ramp.resize((self.width, self.height)).convert("RGBA")

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
