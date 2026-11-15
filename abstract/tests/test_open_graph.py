import datetime
import io

import pytest
from django.core.cache import cache
from PIL import Image

from abstract.open_graph import OpenGraphImage

CACHE_HIT = "render must not draw on a cache hit"


class Card(OpenGraphImage):
    def draw(self, image):
        image.paste((10, 20, 30, 255), (0, 0, 10, 10))


class Undrawable(OpenGraphImage):
    def draw(self, image):
        raise AssertionError(CACHE_HIT)


class TestOpenGraphImage:
    def test_font__returns_the_requested_size(self):
        image = Card(cache_key="font", cache_ttl=datetime.timedelta(minutes=1))

        assert image.font("fira-sans-500.ttf", 32).size == 32

    def test_background__runs_the_brand_gradient_corner_to_corner(self):
        image = Card(cache_key="bg", cache_ttl=datetime.timedelta(minutes=1))

        background = image.background()

        assert background.size == (Card.WIDTH_PX, Card.HEIGHT_PX)
        assert background.mode == "RGBA"
        assert background.getpixel((0, 0)) == (*Card.BACKGROUND_START, 255)
        assert background.getpixel((Card.WIDTH_PX - 1, Card.HEIGHT_PX - 1)) == (
            *Card.BACKGROUND_END,
            255,
        )

    def test_draw__is_abstract(self):
        image = OpenGraphImage(
            cache_key="draw", cache_ttl=datetime.timedelta(minutes=1)
        )

        with pytest.raises(NotImplementedError):
            image.draw(Image.new("RGBA", (1, 1)))

    def test_render__returns_a_png_and_caches_it(self):
        cache.clear()
        image = Card(cache_key="render", cache_ttl=datetime.timedelta(minutes=1))

        payload = image.render()

        assert payload.startswith(b"\x89PNG\r\n\x1a\n")
        assert cache.get("render") == payload
        assert Image.open(io.BytesIO(payload)).size == (
            Card.WIDTH_PX,
            Card.HEIGHT_PX,
        )

    def test_render__serves_the_cached_bytes_without_drawing(self):
        cache.clear()
        cache.set("cached", b"payload", 60)
        image = Undrawable(cache_key="cached", cache_ttl=datetime.timedelta(minutes=1))

        assert image.render() == b"payload"
