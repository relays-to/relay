import dataclasses
import datetime
import io
import pathlib
import typing

from django.core.cache import cache
from PIL import Image, ImageFont

type RGB = tuple[int, int, int]


@dataclasses.dataclass(kw_only=True)
class OpenGraphImage:
    """Render a share card on relay's brand background."""

    cache_key: str
    cache_ttl: datetime.timedelta

    WIDTH_PX: typing.ClassVar[int] = 1200
    HEIGHT_PX: typing.ClassVar[int] = 630
    # The favicon gradient: #6200d1 to #14b8a6.
    BACKGROUND_START: typing.ClassVar[RGB] = (98, 0, 209)
    BACKGROUND_END: typing.ClassVar[RGB] = (20, 184, 166)
    INK: typing.ClassVar[RGB] = (255, 255, 255)
    FONTS_DIR: typing.ClassVar[pathlib.Path] = pathlib.Path(__file__).with_name("fonts")

    def font(self, name: str, size: int) -> ImageFont.FreeTypeFont:
        return ImageFont.truetype(str(self.FONTS_DIR / name), size)

    def background(self) -> Image.Image:
        start, end = self.BACKGROUND_START, self.BACKGROUND_END
        # The favicon angle, corner to corner. A tenth of the canvas holds the
        # same ramp, and bilinear upscaling keeps it smooth.
        small = Image.new("RGB", (self.WIDTH_PX // 10, self.HEIGHT_PX // 10))
        for y in range(small.height):
            for x in range(small.width):
                step = (x / (small.width - 1) + y / (small.height - 1)) / 2
                small.putpixel(
                    (x, y),
                    tuple(round(a + (b - a) * step) for a, b in zip(start, end)),
                )
        return small.resize((self.WIDTH_PX, self.HEIGHT_PX)).convert("RGBA")

    def draw(self, image: Image.Image) -> None:
        raise NotImplementedError

    def render(self) -> bytes:
        if not (payload := cache.get(self.cache_key)):
            image = self.background()
            overlay = Image.new("RGBA", (self.WIDTH_PX, self.HEIGHT_PX), (0, 0, 0, 0))
            self.draw(overlay)
            image = Image.alpha_composite(image, overlay)
            buffer = io.BytesIO()
            image.convert("RGB").save(buffer, format="PNG", optimize=True)
            payload = buffer.getvalue()
            cache.set(self.cache_key, payload, timeout=self.cache_ttl.total_seconds())
        return payload
