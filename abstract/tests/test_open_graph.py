import datetime as dt
import io

import pytest
from django.core import signing
from django.core.cache import cache
from PIL import Image

from abstract.open_graph import BrandImage, OpenGraphImage, TitleImage

CACHE_HIT = "render must not draw on a cache hit"


class Card(OpenGraphImage):
    def draw(self, image):
        image.paste((10, 20, 30, 255), (0, 0, 10, 10))


class Undrawable(OpenGraphImage):
    def draw(self, image):
        raise AssertionError(CACHE_HIT)


class TestOpenGraphImage:
    def test_font__returns_the_requested_size(self):
        image = Card(cache_key="font", cache_ttl=dt.timedelta(minutes=1))

        assert image.font("fira-sans-500.ttf", 32).size == 32

    def test_background__blends_the_four_brand_points(self):
        image = Card(cache_key="bg", cache_ttl=dt.timedelta(minutes=1))

        background = image.background()

        assert background.size == (Card.WIDTH_PX, Card.HEIGHT_PX)
        assert background.mode == "RGBA"
        top_left, top_right, bottom_right, bottom_left = Card.BACKGROUND_POINTS
        # The upscale can shift a channel a single step at the corners.
        assert background.getpixel((0, 0)) == pytest.approx((*top_left, 255), abs=1)
        assert background.getpixel((Card.WIDTH_PX - 1, 0)) == pytest.approx(
            (*top_right, 255), abs=1
        )
        assert background.getpixel(
            (Card.WIDTH_PX - 1, Card.HEIGHT_PX - 1)
        ) == pytest.approx((*bottom_right, 255), abs=1)
        assert background.getpixel((0, Card.HEIGHT_PX - 1)) == pytest.approx(
            (*bottom_left, 255), abs=1
        )

    def test_draw__is_abstract(self):
        image = OpenGraphImage(cache_key="draw", cache_ttl=dt.timedelta(minutes=1))

        with pytest.raises(NotImplementedError):
            image.draw(Image.new("RGBA", (1, 1)))

    def test_render__returns_a_png_and_caches_it(self):
        cache.clear()
        image = Card(cache_key="render", cache_ttl=dt.timedelta(minutes=1))

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
        image = Undrawable(cache_key="cached", cache_ttl=dt.timedelta(minutes=1))

        assert image.render() == b"payload"


class TestBrandImage:
    def test_render__returns_the_default_card(self):
        cache.clear()
        image = BrandImage(cache_key="brand", cache_ttl=dt.timedelta(minutes=1))

        payload = image.render()

        assert payload.startswith(b"\x89PNG\r\n\x1a\n")
        assert Image.open(io.BytesIO(payload)).size == (
            BrandImage.WIDTH_PX,
            BrandImage.HEIGHT_PX,
        )


class TestTitleSigning:
    def test_signer__round_trips(self):
        signer = signing.Signer(salt="open-graph")

        assert signer.unsign(signer.sign("Message log")) == "Message log"

    def test_signer__rejects_a_forged_token(self):
        signer = signing.Signer(salt="open-graph")

        with pytest.raises(signing.BadSignature):
            signer.unsign("Message log")


class TestTitleImage:
    def make_image(self, title: str) -> TitleImage:
        return TitleImage(
            title=title,
            cache_key="title",
            cache_ttl=dt.timedelta(minutes=1),
        )

    def test_render__returns_a_title_card(self):
        cache.clear()

        payload = self.make_image("Message log").render()

        assert payload.startswith(b"\x89PNG\r\n\x1a\n")
        assert Image.open(io.BytesIO(payload)).size == (
            TitleImage.WIDTH_PX,
            TitleImage.HEIGHT_PX,
        )

    @pytest.mark.parametrize(
        "title",
        [
            "",
            "relay: communication as a service",
            "A" * 200,
            " ".join(["a long page title"] * 20),
        ],
    )
    def test_render__fits_any_title(self, title):
        cache.clear()

        assert self.make_image(title).render()
