import datetime as dt
import io

import pytest
from django.core.cache import cache
from PIL import Image

from abstract.open_graph import OpenGraphImage
from domains.check.open_graph import DomainCheckImage
from domains.models import DomainCheck


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()


def make_image(name="example.com", status=DomainCheck.Status.COMPLETE, penalty=0):
    check = DomainCheck(
        name=name,
        status=status,
        penalty=penalty,
        checks=[],
    )
    return DomainCheckImage(
        check=check,
        host="relay.to",
        cache_key=f"card:{name}:{status}:{penalty}",
        cache_ttl=dt.timedelta(minutes=1),
    )


class TestTierColor:
    def test_tier_color__uses_the_tier_colour_when_complete(self):
        image = make_image(penalty=0)

        assert image.tier_color() == image.check.tier.color

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.FAILED]
    )
    def test_tier_color__uses_the_ink_while_incomplete(self, status):
        image = make_image(status=status)

        assert image.tier_color() == OpenGraphImage.INK

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.FAILED]
    )
    def test_tier_accent__is_empty_while_incomplete(self, status):
        image = make_image(status=status)

        assert image.tier_accent() is None


class TestRender:
    def test_render__returns_a_share_card(self):
        image = make_image()

        payload = image.render()

        assert payload.startswith(b"\x89PNG\r\n\x1a\n")
        assert Image.open(io.BytesIO(payload)).size == (
            DomainCheckImage.WIDTH_PX,
            DomainCheckImage.HEIGHT_PX,
        )

    def test_render__serves_the_cached_card(self):
        image = make_image()
        cache.set(image.cache_key, b"cached card")

        assert image.render() == b"cached card"

    def test_render__stores_the_card(self):
        image = make_image()

        payload = image.render()

        assert cache.get(image.cache_key) == payload

    @pytest.mark.parametrize(
        ("status", "penalty"),
        [
            (DomainCheck.Status.COMPLETE, 0),
            (DomainCheck.Status.COMPLETE, 1),
            (DomainCheck.Status.COMPLETE, 8),
            (DomainCheck.Status.COMPLETE, 12),
            (DomainCheck.Status.RUNNING, 0),
            (DomainCheck.Status.FAILED, 0),
        ],
    )
    def test_render__draws_every_tier(self, status, penalty):
        assert make_image(status=status, penalty=penalty).render()

    def test_render__draws_s_in_gold_and_platinum(self):
        image = make_image(penalty=0)
        card = Image.open(io.BytesIO(image.render())).convert("RGB")
        center_x, center_y = DomainCheckImage.TIER_CENTER_PX
        inset = DomainCheckImage.TIER_RADIUS_PX - image.check.tier.ring_width // 2

        lit = card.getpixel((center_x, center_y - inset))
        shaded = card.getpixel((center_x, center_y + inset))

        assert lit[2] < 120
        assert shaded[2] > 180


class TestDrawDomain:
    @pytest.mark.parametrize(
        "name",
        [
            "example.com",
            "a" * 20 + ".example.com",
            "a" * 100 + ".example.com",
            "a" * 100,
            "sub." + "a" * 30 + ".example.com",
        ],
    )
    def test_draw_domain__fits_long_names(self, name):
        assert make_image(name=name).render()
