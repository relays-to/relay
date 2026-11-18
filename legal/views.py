from django.utils.translation import gettext_lazy as _

from abstract.views import MarkdownView

from .content import LegalContent


class ImprintView(MarkdownView):
    title = _("imprint")
    markdown_template = "imprint.md"
    parent = "home"
    content = LegalContent


class TermsView(MarkdownView):
    title = _("terms of service")
    markdown_template = "terms.md"
    parent = "home"
    content = LegalContent


class PrivacyView(MarkdownView):
    title = _("privacy policy")
    markdown_template = "privacy.md"
    parent = "home"
    content = LegalContent
