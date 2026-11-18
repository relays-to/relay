import pytest
from django.apps import apps
from django.urls import reverse


class TestRobotsTxt:
    def test_get__returns_robots_txt(self, client):
        response = client.get(reverse("well_known:robots-txt"))
        assert response.status_code == 200
        assert "text/plain" in response["Content-Type"]
        body = response.content.decode()
        assert "User-agent: *" in body
        assert "Sitemap:" in body
        assert "/sitemap.xml" in body

    def test_get__short_public_cache(self, client):
        response = client.get(reverse("well_known:robots-txt"))
        assert response.headers["Cache-Control"] == "public, max-age=300"


class TestLlmsTxt:
    def test_get__returns_llms_txt(self, client):
        response = client.get(reverse("well_known:llms-txt"))
        assert response.status_code == 200
        assert "text/plain" in response["Content-Type"]
        body = response.content.decode()
        assert body.startswith("# relay")
        assert "> B2B SaaS" in body
        assert "## Know how" in body
        assert "## Legal" in body
        assert "DMARC" in body
        assert "Imprint" in body

    def test_get__contains_article_links(self, client):
        response = client.get(reverse("well_known:llms-txt"))
        body = response.content.decode()
        assert "/know-how/dmarc/" in body
        assert "/know-how/spf/" in body

    def test_get__contains_legal_links(self, client):
        response = client.get(reverse("well_known:llms-txt"))
        body = response.content.decode()
        assert "/legal/imprint/" in body
        assert "/legal/terms/" in body
        assert "/legal/privacy/" in body

    def test_get__contains_alternative_to_section(self, client):
        response = client.get(reverse("well_known:llms-txt"))
        body = response.content.decode()
        assert "## Alternative to" in body
        assert "/alternative-to/ses/" in body
        assert "/alternative-to/sendgrid/" in body

    def test_get__contains_docs_section(self, client):
        response = client.get(reverse("well_known:llms-txt"))
        body = response.content.decode()
        assert "## Docs" in body
        assert "/docs/security/" in body
        assert "/docs/deliverability/" in body


class TestLlmsFullTxt:
    def test_get__returns_full_text(self, client):
        response = client.get(reverse("well_known:llms-full-txt"))
        assert response.status_code == 200
        assert "text/plain" in response["Content-Type"]
        body = response.content.decode()
        assert "relay. Docs (full text)" in body
        assert "DMARC" in body
        assert "SPF" in body

    def test_get__includes_article_content(self, client):
        response = client.get(reverse("well_known:llms-full-txt"))
        body = response.content.decode()
        assert "TL;DR" in body
        assert "RFC 7489" in body

    def test_get__includes_docs_content(self, client):
        response = client.get(reverse("well_known:llms-full-txt"))
        body = response.content.decode()
        assert "# Security" in body
        assert "store-and-forward" in body
        assert "/docs/security/" in body

    def test_get__includes_comparison_content(self, client):
        response = client.get(reverse("well_known:llms-full-txt"))
        body = response.content.decode()
        assert "Alternative to Amazon SES" in body
        assert "/alternative-to/ses/" in body


@pytest.mark.django_db
class TestSitemapIndex:
    def test_get__returns_sitemap_index_xml(self, client):
        response = client.get(reverse("well_known:sitemap"))
        assert response.status_code == 200
        assert "application/xml" in response["Content-Type"]
        body = response.content.decode()
        assert "<sitemapindex" in body
        assert "</sitemapindex>" in body

    def test_get__short_public_cache(self, client):
        response = client.get(reverse("well_known:sitemap"))
        assert response.headers["Cache-Control"] == "public, max-age=300"

    def test_get__links_to_every_section(self, client):
        response = client.get(reverse("well_known:sitemap"))
        body = response.content.decode()
        for section in [
            "home",
            "legal",
            "docs",
            "know-how",
            "alternative-to",
            "domain-check",
            "domain-check-results",
        ]:
            url = reverse("well_known:sitemap-section", kwargs={"section": section})
            assert url in body


class TestSitemapSection:
    def test_get__returns_sitemap_xml(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "know-how"})
        )
        assert response.status_code == 200
        assert "application/xml" in response["Content-Type"]
        body = response.content.decode()
        assert "<urlset" in body
        assert "<url>" in body
        assert "</url>" in body

    def test_get__short_public_cache(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "know-how"})
        )
        assert response.headers["Cache-Control"] == "public, max-age=300"

    def test_get__contains_know_how_articles(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "know-how"})
        )
        body = response.content.decode()
        assert "/know-how/dmarc/" in body
        assert "/know-how/spf/" in body

    def test_get__contains_legal_pages(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "legal"})
        )
        body = response.content.decode()
        assert "/legal/imprint/" in body
        assert "/legal/terms/" in body
        assert "/legal/privacy/" in body

    def test_get__contains_alternative_to_articles(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "alternative-to"})
        )
        body = response.content.decode()
        assert "/alternative-to/ses/" in body
        assert "/alternative-to/sendgrid/" in body

    def test_get__contains_docs_articles(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "docs"})
        )
        body = response.content.decode()
        assert "/docs/security/" in body
        assert "/docs/deliverability/" in body

    @pytest.mark.django_db
    def test_get__contains_domain_checks(self, client):
        apps.get_model("domains", "DomainCheck").objects.create(
            name="example.com",
            status="complete",
        )
        response = client.get(
            reverse(
                "well_known:sitemap-section",
                kwargs={"section": "domain-check-results"},
            )
        )
        body = response.content.decode()
        assert "/domain-check/example.com/" in body

    def test_get__unknown_section_returns_404(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "unknown"})
        )
        assert response.status_code == 404

    def test_get__includes_lastmod(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "docs"})
        )

        assert "<lastmod>" in response.content.decode()

    def test_get__sets_last_modified_header(self, client):
        response = client.get(
            reverse("well_known:sitemap-section", kwargs={"section": "legal"})
        )

        assert response.headers["Last-Modified"]
