from django.utils.translation import gettext_lazy as _

from abstract.views import MarkdownView

from .content import LegalContent


class LegalView(MarkdownView):
    """Render a legal page with the service contact details."""

    parent = "home"
    content = LegalContent

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {
            "site_name": "relay",
            "contact_email": "postmaster@relays.to",
        }


class ImprintView(LegalView):
    title = _("imprint")
    markdown_template = "imprint.md"


class TermsView(LegalView):
    title = _("terms of service")
    markdown_template = "terms.md"


class PrivacyView(LegalView):
    title = _("privacy policy")
    markdown_template = "privacy.md"
