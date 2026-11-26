import datetime as dt
import re
from urllib.parse import quote

import pytest
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

from accounts.models import Membership, Organization
from domains.models import Domain, DomainCheck, canonicalize_domain_name


class Queue:
    def __init__(self):
        self.calls = []

    def enqueue(self, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def queue(monkeypatch):
    stub = Queue()
    monkeypatch.setattr("domains.check.tasks.check_domain", stub)
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
    }
    fields.update(kwargs)
    return DomainCheck.objects.create(**fields)


def backdate(check, **delta):
    DomainCheck.objects.filter(pk=check.pk).update(
        modified_at=timezone.now() - dt.timedelta(**delta)
    )
    check.refresh_from_db()
    return check


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
        assert response.headers["Cache-Control"] == (
            "private, max-age=5, must-revalidate"
        )
        assert "ETag" in response.headers

    def test_get__revalidates_with_an_etag(self, client):
        make_check()
        etag = client.get("/domain-check/").headers["ETag"]

        response = client.get("/domain-check/", headers={"If-None-Match": etag})

        assert response.status_code == 304

    def test_get__changes_the_etag_when_a_row_is_added(self, client):
        etag = client.get("/domain-check/").headers["ETag"]
        make_check()

        response = client.get("/domain-check/", headers={"If-None-Match": etag})

        assert response.status_code == 200
        assert response.headers["ETag"] != etag

    def test_get__shows_domain_icons(self, client):
        make_check(name="example.com")

        response = client.get("/domain-check/")

        assert (
            'src="https://favicon.vemetric.com/example.com?size=96"'
            in response.content.decode()
        )

    def test_get__lists_every_status(self, client):
        make_check()
        make_check(name="failed.example", status=DomainCheck.Status.FAILED)
        make_check(name="running.example", status=DomainCheck.Status.RUNNING)

        response = client.get("/domain-check/")

        assert {row.name for row in response.context["page_obj"]} == {
            "example.com",
            "failed.example",
            "running.example",
        }
        assert set(
            re.findall(r'href="/domain-check/([\w.-]+)/"', response.content.decode())
        ) == {
            "example.com",
            "failed.example",
            "running.example",
        }

    def test_get__orders_by_tier_then_most_recent(self, client):
        make_check(name="broken.example", penalty=4)
        backdate(make_check(name="older.example", penalty=0), hours=1)
        make_check(name="recent.example", penalty=0)

        response = client.get("/domain-check/")

        assert [row.name for row in response.context["page_obj"]] == [
            "recent.example",
            "older.example",
            "broken.example",
        ]

    def test_get__prefills_the_form_from_the_query(self, client):
        response = client.get("/domain-check/?name=example.com")

        assert response.context["form"]["name"].value() == "example.com"

    def test_get__paginates(self, client):
        for index in range(51):
            make_check(name=f"domain{index}.example")

        response = client.get("/domain-check/?page=2")

        assert len(response.context["page_obj"]) == 1


class TestDomainCheckSubmitView:
    def test_get__redirects_to_the_list(self, client):
        response = client.get("/domain-check/submit")

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/"

    @pytest.mark.django_db
    def test_post__creates_and_queues_a_new_domain(self, client, queue):
        response = client.post("/domain-check/submit", {"name": "Example.COM"})

        domain_check = DomainCheck.objects.get()
        assert domain_check.name == "example.com"
        assert queue.calls == [{"name": "example.com"}]
        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/example.com/"

    @pytest.mark.django_db
    def test_post__keeps_a_fresh_result(self, client, queue):
        make_check()

        response = client.post("/domain-check/submit", {"name": "example.com"})

        assert queue.calls == []
        assert [str(message) for message in get_messages(response.wsgi_request)] == [
            "This domain was checked less than a day ago."
        ]

    @pytest.mark.django_db
    def test_post__queues_a_stale_result(self, client, queue):
        backdate(make_check(), days=2)

        client.post("/domain-check/submit", {"name": "example.com"})

        assert queue.calls == [{"name": "example.com"}]

    @pytest.mark.django_db
    def test_post__rejects_an_internal_suffix(self, client, queue):
        response = client.post("/domain-check/submit", {"name": "printer.local"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/"
        assert [str(message) for message in get_messages(response.wsgi_request)] == [
            "Enter a public domain name, for example acme.com"
        ]
        assert not DomainCheck.objects.exists()
        assert queue.calls == []

    def test_post__rejects_an_invalid_domain(self, client):
        response = client.post("/domain-check/submit", {"name": "not a domain"})

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/"
        assert [str(message) for message in get_messages(response.wsgi_request)] == [
            "Enter a valid domain name, for example acme.com"
        ]


@pytest.mark.django_db
class TestDomainCheckDetailView:
    def test_get__renders_a_complete_check(self, client):
        make_full_check()

        response = client.get("/domain-check/example.com/")

        assert response.status_code == 200
        assert "domain_check/domaincheck_detail.html" in [
            t.name for t in response.templates
        ]
        assert response.headers["Cache-Control"] == (
            "private, max-age=5, must-revalidate"
        )
        assert "ETag" in response.headers
        content = response.content.decode()
        assert "3 issues need attention" in content
        assert "MX record" in content
        assert "SPF record" in content
        assert "Blocklists detail" in content
        assert "Learn more" in content
        assert "8.8.8.8" in content
        assert "Fix:" in content

    def test_get__renders_a_markdown_hint(self, client):
        make_check(
            checks=[
                make_row(
                    "mx",
                    "MX",
                    "partial",
                    [
                        {
                            "label": "Google Workspace",
                            "status": "fail",
                            "detail": "Legacy MX records",
                            "severity": "weak",
                        }
                    ],
                )
            ]
        )

        response = client.get("/domain-check/example.com/")

        content = response.content.decode()
        assert (
            '<a href="https://knowledge.workspace.google.com/admin/domains/'
            'set-up-mx-records-for-google-workspace">Update the MX records</a>'
        ) in content

    def test_get__escapes_raw_html_in_a_markdown_hint(self, client):
        make_check(
            checks=[
                make_row(
                    "dmarc",
                    "DMARC",
                    "fail",
                    [
                        {
                            "label": "DMARC record",
                            "status": "fail",
                            "detail": "none",
                            "severity": "blocking",
                        }
                    ],
                )
            ]
        )

        response = client.get("/domain-check/example.com/")

        assert "_dmarc.&lt;domain&gt;" in response.content.decode()

    def test_get__revalidates_with_an_etag(self, client):
        make_check()
        etag = client.get("/domain-check/example.com/").headers["ETag"]

        response = client.get(
            "/domain-check/example.com/", headers={"If-None-Match": etag}
        )

        assert response.status_code == 304

    def test_get__changes_the_etag_when_the_check_changes(self, client):
        check = make_check()
        etag = client.get("/domain-check/example.com/").headers["ETag"]
        DomainCheck.objects.filter(pk=check.pk).update(
            status=DomainCheck.Status.RUNNING,
            modified_at=timezone.now(),
        )

        response = client.get(
            "/domain-check/example.com/", headers={"If-None-Match": etag}
        )

        assert response.status_code == 200
        assert response.headers["ETag"] != etag

    def test_get__renders_a_clean_check(self, client):
        make_check()

        response = client.get("/domain-check/example.com/")

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

        response = client.get("/domain-check/example.com/")

        assert "1 issue needs attention" in response.content.decode()

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING]
    )
    def test_get__polls_a_running_check(self, client, status):
        make_check(status=status)

        response = client.get("/domain-check/example.com/")

        assert "domain_check/domaincheck_checking.html" in [
            t.name for t in response.templates
        ]
        assert 2 <= response.context["refresh_secs"] <= 4

    def test_get__renders_a_failed_check(self, client):
        make_check(status=DomainCheck.Status.FAILED)

        response = client.get("/domain-check/example.com/")

        assert "domain_check/domaincheck_detail.html" in [
            t.name for t in response.templates
        ]
        assert "The last check failed." in response.content.decode()

    def test_get__redirects_to_the_canonical_name(self, client):
        make_check()

        response = client.get("/domain-check/EXAMPLE.com/")

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/example.com/"

    def test_get__redirects_an_idn_name(self, client):
        make_check(name="xn--mnich-kva.com")

        response = client.get(f"/domain-check/{quote('münich.com')}/")

        assert response.headers["Location"] == "/domain-check/xn--mnich-kva.com/"

    def test_get__forwards_an_unknown_domain_to_the_list(self, client):
        response = client.get("/domain-check/example.com/")

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/?name=example.com"

    def test_post__requires_login(self, client, queue):
        make_check()

        response = client.post("/domain-check/example.com/")

        assert response.status_code == 302
        assert response.headers["Location"] == (
            "/account/login?next=/domain-check/example.com/"
        )
        assert queue.calls == []

    @pytest.mark.parametrize(
        "status", [DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING]
    )
    def test_post__leaves_a_running_check_alone(self, admin_client, queue, status):
        make_check(status=status)

        response = admin_client.post("/domain-check/example.com/")

        assert response.status_code == 302
        assert queue.calls == []
        assert DomainCheck.objects.get().status == status

    def test_post__restarts_a_complete_check(self, admin_client, queue):
        check = make_full_check()

        response = admin_client.post("/domain-check/example.com/")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.PENDING
        assert check.checks == []
        assert queue.calls == [{"name": "example.com"}]
        assert response.headers["Location"] == "/domain-check/example.com/"

    def test_post__restarts_a_failed_check(self, admin_client, queue):
        check = make_check(status=DomainCheck.Status.FAILED)

        admin_client.post("/domain-check/example.com/")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.PENDING
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
    def test_detail__forwards_an_invalid_name_to_the_list(self, client):
        response = client.get(f"/domain-check/{quote('❤')}/")

        assert response.status_code == 302
        assert response.headers["Location"] == "/domain-check/?name=%E2%9D%A4"

    def test_og_image__rejects_an_invalid_name(self, client):
        response = client.get(f"/domain-check/{quote('❤')}/og.png")

        assert response.status_code == 404


@pytest.mark.django_db
class TestDomainCheckMonitorView:
    def test_get__requires_login(self, client):
        make_check()

        response = client.get("/domain-check/example.com/monitor")

        assert response.status_code == 302
        assert response.headers["Location"] == (
            "/account/login?next=/domain-check/example.com/monitor"
        )

    def test_get__forwards_an_unknown_name(self, admin_client):
        response = admin_client.get("/domain-check/example.com/monitor")

        assert response.status_code == 404

    def test_get__sends_an_orgless_user_to_create_one(self, client, queue):
        make_check()
        client.force_login(User.objects.create_user(username="carol"))

        response = client.get("/domain-check/example.com/monitor")

        assert response.status_code == 302
        assert response.headers["Location"] == reverse("accounts:org-list")
        assert [str(message) for message in get_messages(response.wsgi_request)] == [
            "Create an organization first. Then add the domain to it."
        ]
        assert queue.calls == []

    def test_get__offers_the_org_picker_for_several_orgs(
        self, admin_client, user, org, queue
    ):
        make_check()
        Membership.objects.create(
            org=Organization.objects.create(slug="second"), user=user
        )

        response = admin_client.get("/domain-check/example.com/monitor")

        assert response.status_code == 200
        html = response.content.decode()
        assert '<option value="test-org">test-org</option>' in html
        assert '<option value="second">second</option>' in html
        assert "Monitor example.com | relay" in html
        assert queue.calls == []

    def test_get__monitors_the_only_org(self, admin_client, org, queue):
        make_check()

        response = admin_client.get("/domain-check/example.com/monitor")

        domain = Domain.objects.get(org=org, name="example.com")
        assert response.status_code == 302
        assert response.headers["Location"] == domain.get_absolute_url()
        assert domain.domain_check.name == "example.com"
        assert queue.calls == []

    def test_get__queues_a_stale_monitored_check(self, admin_client, org, queue):
        Domain.objects.create(name="example.com", org=org)

        response = admin_client.get("/domain-check/example.com/monitor")

        assert response.status_code == 302
        assert queue.calls == [{"name": "example.com"}]

    def test_post__requires_login(self, client, queue):
        make_check()

        response = client.post("/domain-check/example.com/monitor")

        assert response.status_code == 302
        assert queue.calls == []

    def test_post__rejects_an_org_the_user_does_not_belong_to(
        self, admin_client, org, write_org, queue
    ):
        make_check()

        response = admin_client.post(
            "/domain-check/example.com/monitor", {"org": write_org.slug}
        )

        assert response.status_code == 404
        assert not Domain.objects.filter(org=org, name="example.com").exists()
        assert queue.calls == []

    def test_post__rejects_the_platform_domain(self, admin_client, org, queue):
        platform = canonicalize_domain_name(settings.PLATFORM_DOMAIN)
        check = make_check(name=platform)

        response = admin_client.post(
            f"/domain-check/{platform}/monitor", {"org": org.slug}
        )

        assert response.status_code == 302
        assert response.headers["Location"] == check.get_absolute_url()
        assert [str(message) for message in get_messages(response.wsgi_request)] == [
            f"Cannot add {platform}. relay manages that zone."
        ]
        assert not Domain.objects.filter(org=org, name=platform).exists()

    def test_post__reports_the_rejection_of_the_domain(self, admin_client, org, queue):
        check = make_check(name="printer.open.localhost")

        response = admin_client.post(
            "/domain-check/printer.open.localhost/monitor", {"org": org.slug}
        )

        assert response.status_code == 302
        assert response.headers["Location"] == check.get_absolute_url()
        assert [
            (message.level_tag, str(message))
            for message in get_messages(response.wsgi_request)
        ] == [
            (
                "error",
                "Cannot add a subdomain of open.localhost. relay manages these automatically.",
            )
        ]
        assert not Domain.objects.filter(
            org=org, name="printer.open.localhost"
        ).exists()

    def test_post__rejects_a_name_another_org_already_owns(
        self, admin_client, org, write_org, queue
    ):
        Domain.objects.create(name="example.com", org=write_org)
        check = DomainCheck.objects.get(name="example.com")

        response = admin_client.post(
            "/domain-check/example.com/monitor", {"org": org.slug}
        )

        assert response.status_code == 302
        assert response.headers["Location"] == check.get_absolute_url()
        assert not Domain.objects.filter(org=org, name="example.com").exists()
        assert queue.calls == []

    def test_post__creates_and_monitors_a_new_domain(self, admin_client, org, queue):
        make_check()

        response = admin_client.post(
            "/domain-check/example.com/monitor", {"org": org.slug}
        )

        domain = Domain.objects.get(org=org, name="example.com")
        assert response.status_code == 302
        assert response.headers["Location"] == domain.get_absolute_url()
        assert domain.domain_check.name == "example.com"
        assert queue.calls == []

    def test_post__monitors_an_existing_domain(self, admin_client, org, queue):
        Domain.objects.create(name="example.com", org=org)

        response = admin_client.post(
            "/domain-check/example.com/monitor", {"org": org.slug}
        )

        domain = Domain.objects.get(org=org, name="example.com")
        assert response.status_code == 302
        assert response.headers["Location"] == domain.get_absolute_url()
        assert queue.calls == [{"name": "example.com"}]

    def test_post__keeps_a_fresh_check(self, admin_client, org, queue):
        Domain.objects.create(name="example.com", org=org)
        DomainCheck.objects.filter(name="example.com").update(
            status=DomainCheck.Status.COMPLETE
        )

        response = admin_client.post(
            "/domain-check/example.com/monitor", {"org": org.slug}
        )

        assert response.status_code == 302
        assert queue.calls == []
