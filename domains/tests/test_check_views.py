import datetime
import re
from urllib.parse import quote

import pytest
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.utils import timezone

from domains.models import DomainCheck


class Queue:
    def __init__(self):
        self.calls = []

    def enqueue(self, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def queue(monkeypatch):
    stub = Queue()
    monkeypatch.setattr("domains.check.views.check_domain", stub)
    return stub


@pytest.fixture(autouse=True)
def clear_cache():
    cache.clear()


def make_row(key, label, status, subchecks=()):
    return {
        "key": key,
        "label": label,
        "status": status,
        "detail": f"{label} detail",
        "subchecks": list(subchecks),
    }


def make_check(**kwargs):
    fields = {
        "name": "example.com",
        "status": DomainCheck.Status.COMPLETE,
        "penalty": 0,
        "checks": [],
        "checked_at": timezone.now(),
    }
    fields.update(kwargs)
    return DomainCheck.objects.create(**fields)


def make_full_check(**kwargs):
    checks = [
        make_row(
            "mx",
            "MX",
            "partial",
            [
                {"label": "MX record", "status": "pass", "detail": "one"},
                {
                    "label": "MX TTL",
                    "status": "fail",
                    "detail": "30 minutes",
                    "severity": "weak",
                },
            ],
        ),
        make_row(
            "spf",
            "SPF",
            "fail",
            [
                {
                    "label": "SPF record",
                    "status": "fail",
                    "detail": "none",
                    "severity": "blocking",
                    "addresses": ["8.8.8.8"],
                },
                {"label": "Lookup limit", "status": "skip", "detail": "n/a"},
                {
                    "label": "Strict all",
                    "status": "fail",
                    "detail": "~all",
                    "severity": "weak",
                },
            ],
        ),
        make_row("blocklists", "Blocklists", "pass"),
    ]
    return make_check(checks=checks, **kwargs)


@pytest.mark.django_db
class TestDomainCheckListView:
    def test_get__renders_the_empty_state(self, client):
        response = client.get("/domain-check/")

        assert response.status_code == 200
        assert "No domains checked yet." in response.content.decode()
        assert response.headers["Cache-Control"] == "no-store"

    def test_get__lists_every_status(self, client):
        make_check()
        make_check(name="failed.example", status=DomainCheck.Status.FAILED)
        make_check(name="running.example", status=DomainCheck.Status.RUNNING)

        response = client.get("/domain-check/")

        assert [row.name for row in response.context["page_obj"]] == [
            "example.com",
            "failed.example",
            "running.example",
        ]
        assert set(
            re.findall(r'href="/domain-check/([\w.-]+)"', response.content.decode())
        ) == {
            "example.com",
            "failed.example",
            "running.example",
        }

    def test_get__paginates(self, client):
        for index in range(51):
            make_check(name=f"domain{index}.example")

        response = client.get("/domain-check/?page=2")

        assert len(response.context["page_obj"]) == 1

    def test_post__creates_and_queues_a_new_domain(self, client, queue):
        response = client.post("/domain-check/", {"name": "Example.COM"})

        domain_check = DomainCheck.objects.get()
        assert domain_check.name == "example.com"
        assert queue.calls == [{"name": "example.com"}]
        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/example.com"

    def test_post__keeps_a_fresh_result(self, client, queue):
        make_check(checked_at=timezone.now())

        response = client.post("/domain-check/", {"name": "example.com"})

        assert queue.calls == []
        assert [str(message) for message in get_messages(response.wsgi_request)] == [
            "This domain was checked less than a day ago."
        ]

    def test_post__queues_a_stale_result(self, client, queue):
        make_check(checked_at=timezone.now() - datetime.timedelta(days=2))

        client.post("/domain-check/", {"name": "example.com"})

        assert queue.calls == [{"name": "example.com"}]

    def test_post__rejects_an_internal_suffix(self, client, queue):
        response = client.post("/domain-check/", {"name": "printer.local"})

        assert response.status_code == 200
        assert "Enter a public domain name" in response.content.decode()
        assert not DomainCheck.objects.exists()
        assert queue.calls == []

    def test_post__rejects_an_invalid_domain(self, client):
        response = client.post("/domain-check/", {"name": "not a domain"})

        assert response.status_code == 200
        assert "Enter a valid domain name" in response.content.decode()


@pytest.mark.django_db
class TestDomainCheckDetailView:
    def test_get__renders_a_complete_check(self, client):
        make_full_check()

        response = client.get("/domain-check/example.com")

        assert response.status_code == 200
        assert "domain_check/domaincheck_detail.html" in [
            t.name for t in response.templates
        ]
        assert response.headers["Cache-Control"] == "no-store"
        content = response.content.decode()
        assert "3 issues need attention" in content
        assert "MX record" in content
        assert "SPF record" in content
        assert "Blocklists detail" in content
        assert "Learn more" in content
        assert "8.8.8.8" in content
        assert "Fix:" in content

    def test_get__renders_a_clean_check(self, client):
        make_check()

        response = client.get("/domain-check/example.com")

        assert "All checks pass." in response.content.decode()

    def test_get__renders_a_single_issue(self, client):
        make_check(
            checks=[
                make_row(
                    "mx",
                    "MX",
                    "partial",
                    [{"label": "MX TTL", "status": "fail", "detail": "short"}],
                )
            ]
        )

        response = client.get("/domain-check/example.com")

        assert "1 issue needs attention" in response.content.decode()

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING]
    )
    def test_get__polls_a_running_check(self, client, status):
        make_check(status=status, checked_at=None)

        response = client.get("/domain-check/example.com")

        assert "domain_check/domaincheck_checking.html" in [
            t.name for t in response.templates
        ]
        assert 2 <= response.context["refresh_secs"] <= 4

    def test_get__renders_a_failed_check(self, client):
        make_check(status=DomainCheck.Status.FAILED, checked_at=None)

        response = client.get("/domain-check/example.com")

        assert "domain_check/domaincheck_detail.html" in [
            t.name for t in response.templates
        ]
        assert "The last check failed." in response.content.decode()

    def test_get__redirects_to_the_canonical_name(self, client):
        make_check()

        response = client.get("/domain-check/EXAMPLE.com")

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/example.com"

    def test_get__redirects_an_idn_name(self, client):
        make_check(name="xn--mnich-kva.com")

        response = client.get(f"/domain-check/{quote('münich.com')}")

        assert response.headers["Location"] == "/domain-check/xn--mnich-kva.com"

    def test_get__rejects_an_unknown_domain(self, client):
        assert client.get("/domain-check/example.com").status_code == 404

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING]
    )
    def test_post__leaves_a_running_check_alone(self, client, queue, status):
        make_check(status=status, checked_at=None)

        response = client.post("/domain-check/example.com")

        assert response.status_code == 302
        assert queue.calls == []
        assert DomainCheck.objects.get().status == status

    def test_post__restarts_a_complete_check(self, client, queue):
        check = make_full_check()

        response = client.post("/domain-check/example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.RUNNING
        assert check.checks == []
        assert queue.calls == [{"name": "example.com"}]
        assert response.headers["Location"] == "/domain-check/example.com"

    def test_post__restarts_a_failed_check(self, client, queue):
        check = make_check(status=DomainCheck.Status.FAILED)

        client.post("/domain-check/example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.RUNNING
        assert queue.calls == [{"name": "example.com"}]


@pytest.mark.django_db
class TestDomainCheckOgImageView:
    def test_get__renders_a_png(self, client):
        make_check()

        response = client.get("/domain-check/example.com/og.png")

        assert response.status_code == 200
        assert response.headers["Content-Type"] == "image/png"
        assert response.content.startswith(b"\x89PNG\r\n\x1a\n")

    def test_get__sets_the_cache_headers(self, client):
        make_check()

        response = client.get("/domain-check/example.com/og.png")

        assert response.headers["Cache-Control"] == "public, max-age=60, s-maxage=300"

    def test_get__serves_the_cached_card(self, client):
        check = make_check()
        cache.set(
            f"domain_check:open_graph:example.com:testserver:"
            f"{int(check.modified_at.timestamp())}",
            b"cached card",
        )

        response = client.get("/domain-check/example.com/og.png")

        assert response.content == b"cached card"

    def test_get__stores_the_card(self, client):
        check = make_check()

        response = client.get("/domain-check/example.com/og.png")

        assert (
            cache.get(
                f"domain_check:open_graph:example.com:testserver:"
                f"{int(check.modified_at.timestamp())}"
            )
            == response.content
        )

    def test_get__canonicalizes_the_name(self, client):
        make_check()

        response = client.get("/domain-check/EXAMPLE.com/og.png")

        assert response.status_code == 200

    def test_get__rejects_an_unknown_domain(self, client):
        assert client.get("/domain-check/example.com/og.png").status_code == 404


class TestInvalidNames:
    def test_detail__rejects_an_invalid_name(self, client):
        response = client.get(f"/domain-check/{quote('❤')}")

        assert response.status_code == 404

    def test_og_image__rejects_an_invalid_name(self, client):
        response = client.get(f"/domain-check/{quote('❤')}/og.png")

        assert response.status_code == 404
