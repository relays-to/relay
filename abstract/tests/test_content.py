import datetime as dt

import pytest
from django.http import Http404

from abstract.content import MarkdownContent


class TestGetArticles:
    def test_get_articles__returns_the_fixed_index_in_order(self, tmp_path):
        (tmp_path / "beta.md").write_text("---\nname: Beta\n---\nBody.")
        (tmp_path / "alpha.md").write_text("---\nname: Alpha\n---\nBody.")

        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset({"beta", "alpha"})

        articles = dict(TestContent.get_articles())
        assert list(articles) == ["alpha", "beta"]
        assert articles["alpha"]["name"] == "Alpha"

    def test_get_articles__ignores_files_outside_the_index(self, tmp_path):
        (tmp_path / "alpha.md").write_text("---\nname: Alpha\n---\nBody.")
        (tmp_path / "other.md").write_text("---\nname: Other\n---\nBody.")

        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset({"alpha"})

        assert [slug for slug, _ in TestContent.get_articles()] == ["alpha"]


class TestGetArticlePath:
    def test_get_article_path__returns_the_indexed_file(self, tmp_path):
        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset({"alpha"})

        assert TestContent.get_article_path("alpha") == tmp_path / "alpha.md"

    def test_get_article_path__rejects_a_slug_outside_the_index(self, tmp_path):
        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset()

        with pytest.raises(Http404):
            TestContent.get_article_path("unknown")


class TestGetArticleMetadata:
    def test_get_article_metadata__parses_the_frontmatter(self, tmp_path):
        (tmp_path / "alpha.md").write_text("---\nname: Alpha\n---\nBody.")

        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset({"alpha"})

        assert TestContent.get_article_metadata("alpha") == {"name": "Alpha"}


class TestGetArticleModifiedAt:
    def test_get_article_modified_at__parses_a_date(self, tmp_path):
        (tmp_path / "alpha.md").write_text("---\nmodified_at: 2026-10-20\n---\nBody.")

        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset({"alpha"})

        assert TestContent.get_article_modified_at("alpha") == dt.datetime(
            2026, 10, 20, tzinfo=dt.UTC
        )


class TestGetLatestModifiedAt:
    def test_get_latest_modified_at__returns_the_newest_article(self, tmp_path):
        (tmp_path / "alpha.md").write_text("---\nmodified_at: 2026-10-20\n---\nBody.")
        (tmp_path / "beta.md").write_text("---\nmodified_at: 2026-11-03\n---\nBody.")

        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset({"alpha", "beta"})

        assert TestContent.get_latest_modified_at() == dt.datetime(
            2026, 11, 3, tzinfo=dt.UTC
        )

    def test_get_latest_modified_at__returns_none_for_an_empty_index(self, tmp_path):
        class TestContent(MarkdownContent):
            docs_dir = tmp_path
            slugs = frozenset()

        assert TestContent.get_latest_modified_at() is None
