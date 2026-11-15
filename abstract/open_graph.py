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

    def font(self, name: str, size: int) -> ImageFont.FreeTypeFont:
        return ImageFont.truetype(str(self.FONTS_DIR / name), size)

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
