import datetime as dt
import hashlib

from django.conf import settings
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.utils.translation import gettext_lazy as _
from django.views import defaults, generic
from django.views.csrf import csrf_failure

from abstract.open_graph import TitleImage
from abstract.views import (
    PUBLIC_PAGE_CACHE,
    BreadcrumbViewMixin,
    CacheControlMixin,
)

# Wordmarks of companies that back relay, with owner-attested endorsement.
# Optional keys: "url" (endorser link) and "logo" (static image path).

BRANDS = [
    {"name": "Henkel"},
    {"name": "Porsche"},
    {"name": "Thermondo"},
    {"name": "Fizard"},
    {"name": "voiio"},
    {"name": "Sparkasse"},
]

TESTIMONIALS = [
    {
        "quote": "The sandbox is a killer feature. It lets us build faster and better without any infrastructure friction. You just flip a switch, lean back and watch it work.",
        "name": "Rustem Saiargaliev",
        "initials": "AM",
        "role": "Lead Engineer",
        "image": "/static/img/testimonials/rustem-saiargaliev.png",
    },
    {
        "quote": "As a founder, I need tools that get out of the way. We plug relay into any agentic workflow to get immediate access to sending and receiving messages.",
        "name": "Marc Metz",
        "initials": "MM",
        "role": "AI Entrepreneur (YC-W21)",
        "image": "/static/img/testimonials/marc-metz.jpeg",
    },
    {
        "quote": "In marketing, sender reputation is everything. relay ensures our emails actually hit the inbox instead of ending up in spam or on a block list, which is critical for any growing brand.",
        "name": "Sebastian Schirmer",
        "initials": "BS",
        "role": "Marketing Manager",
        "image": "/static/img/testimonials/sebasitan-schirmer.jpeg",
    },
]


class HomeView(CacheControlMixin, BreadcrumbViewMixin, generic.TemplateView):
    """Render the marketing landing page."""

    template_name = "start.html"
    title = _("Home")
    cache_control = PUBLIC_PAGE_CACHE

    def get_context_data(self, **kwargs):
        platform = self.request.get_host().split(":")[0]
        return super().get_context_data(**kwargs) | {
            # The landing page keeps the brand card instead of a title card.
            "page_title": "",
            "nameservers": [f"ns1.{platform}", f"ns2.{platform}"],
            "brands": BRANDS,
            "testimonials": TESTIMONIALS,
            "free_monthly_messages": settings.FREE_MONTHLY_MESSAGES,
            "price_per_1000_messages": settings.PRICE_PER_1000_MESSAGES,
        }


class OpenSourceView(CacheControlMixin, BreadcrumbViewMixin, generic.TemplateView):
    """Render the open-source pledge."""

    template_name = "open_source.html"
    title = _("the open-source pledge")
    parent = "home"
    cache_control = PUBLIC_PAGE_CACHE


class OpenGraphImageView(CacheControlMixin, generic.View):
    """Render a share card for a signed page title as a PNG."""

    CACHE_VERSION = "v1"
    MAX_TITLE_LENGTH = 120
    OG_TTL = dt.timedelta(days=1)
    cache_control = {
        "public": True,
        "max_age": OG_TTL,
        "s_maxage": OG_TTL,
    }

    def get(self, request, *args, **kwargs):
        try:
            title = signing.Signer(salt="open-graph").unsign(
                request.GET.get("signature", "")
            )
        except signing.BadSignature as error:
            raise Http404 from error
        title = " ".join(title.split())[: self.MAX_TITLE_LENGTH]
        if not title:
            raise Http404
        image = TitleImage(
            title=title,
            cache_key=(
                f"open_graph:title:{self.CACHE_VERSION}:"
                f"{hashlib.sha256(title.encode()).hexdigest()}"
            ),
            cache_ttl=self.OG_TTL,
        ).render()
        return HttpResponse(image, content_type="image/png")


class Error400PreviewView(generic.View):
    """Render the production 400 page so DEBUG mode can preview it."""

    def get(self, request):
        return defaults.bad_request(request, Exception("Preview"))


class Error403PreviewView(generic.View):
    """Render the production 403 page so DEBUG mode can preview it."""

    def get(self, request):
        return defaults.permission_denied(request, PermissionDenied("Preview"))


class Error403CSRFPreviewView(generic.View):
    """Render the production CSRF failure page so DEBUG mode can preview it."""

    def get(self, request):
        return csrf_failure(request, reason="CSRF token missing.")


class Error404PreviewView(generic.View):
    """Render the production 404 page so DEBUG mode can preview it."""

    def get(self, request):
        return defaults.page_not_found(request, Http404("Preview"))


class Error500PreviewView(generic.View):
    """Render the production 500 page so DEBUG mode can preview it."""

    def get(self, request):
        return defaults.server_error(request)
