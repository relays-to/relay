"""Legal page index, independent of Django views."""

import pathlib

from django.conf import settings

from abstract.content import MarkdownContent

LEGAL_DIR = pathlib.Path(settings.BASE_DIR) / "legal" / "docs"
SLUGS = frozenset(p.stem for p in LEGAL_DIR.glob("*.md"))


class LegalContent(MarkdownContent):
    docs_dir = LEGAL_DIR
    slugs = SLUGS
