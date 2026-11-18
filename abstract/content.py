"""Markdown article indexing that does not depend on Django views."""

import datetime as dt
import pathlib

import frontmatter
from django.http import Http404


class MarkdownContent:
    """
    Content index for Markdown articles served from a docs directory.

    Subclasses set `docs_dir` and the fixed `slugs` index.
    """

    docs_dir: pathlib.Path
    slugs: frozenset[str]

    @classmethod
    def get_article_path(cls, slug: str) -> pathlib.Path:
        """Return the indexed file, or raise `Http404` for an unknown slug."""
        if slug in cls.slugs:
            return cls.docs_dir / f"{slug}.md"
        raise Http404

    @classmethod
    def get_article(cls, slug: str) -> frontmatter.Post:
        """Return the parsed article of one slug."""
        return frontmatter.load(cls.get_article_path(slug))

    @classmethod
    def get_articles(cls):
        """Yield `(slug, metadata)` for each article in the fixed index."""
        for slug in sorted(cls.slugs):
            yield slug, cls.get_article(slug).metadata

    @classmethod
    def get_article_metadata(cls, slug: str) -> dict[str, str]:
        """Return the front matter of one article."""
        return cls.get_article(slug).metadata

    @classmethod
    def get_article_modified_at(cls, slug: str) -> dt.datetime:
        """Return the modification time of one article as an aware UTC datetime."""
        return dt.datetime.combine(
            cls.get_article_metadata(slug)["modified_at"],
            dt.time.min,
            tzinfo=dt.UTC,
        )

    @classmethod
    def get_latest_modified_at(cls) -> dt.datetime | None:
        """Return the newest article modification, or `None` for an empty index."""
        return max(
            (cls.get_article_modified_at(slug) for slug in cls.slugs),
            default=None,
        )
