import pytest
from django.contrib import admin
from django.contrib.auth.models import Permission, User
from django.tasks import task_backends
from django.urls import reverse

from domains.admin import DomainAdmin, DomainCheckAdmin
from domains.models import Domain, DomainCheck


@pytest.fixture
def task_results(settings):
    settings.TASKS = {
        "default": {
            "BACKEND": "root.backends.DummyRetryBackend",
            "QUEUES": settings.TASK_QUEUES,
        },
    }
    return task_backends["default"].results


class TestDomainAdmin:
    def test_domain_admin__registered(self):
        assert isinstance(admin.site._registry[Domain], DomainAdmin)

    def test_domain_admin__list_display(self):
        assert "name" in DomainAdmin.list_display
        assert "org" in DomainAdmin.list_display
        assert "verified_at" in DomainAdmin.list_display
        assert "nameserver_status" in DomainAdmin.list_display

    def test_domain_admin__search_fields(self):
        assert "name" in DomainAdmin.search_fields
        assert "org__slug" in DomainAdmin.search_fields

    @pytest.mark.django_db
    def test_domain_admin__changelist_search_by_org_slug(self, client, admin_user, org):
        domain = Domain.objects.create(name="example.com", org=org)
        client.force_login(admin_user)

        response = client.get(
            reverse("admin:domains_domain_changelist"),
            {"q": org.slug},
        )

        assert response.status_code == 200
        assert domain in response.context["cl"].result_list


class TestDomainCheckAdmin:
    def test_domain_check_admin__registered(self):
        assert isinstance(admin.site._registry[DomainCheck], DomainCheckAdmin)

    def test_domain_check_admin__readonly_generated_fields(self):
        assert "checks" in DomainCheckAdmin.readonly_fields
        assert "status" in DomainCheckAdmin.readonly_fields
        assert "penalty" in DomainCheckAdmin.readonly_fields

    def test_has_add_permission__denied(self, rf):
        model_admin = admin.site._registry[DomainCheck]
        assert model_admin.has_add_permission(rf.get("/admin/")) is False

    def test_recheck__registered(self):
        assert "recheck" in DomainCheckAdmin.actions

    @pytest.mark.django_db
    def test_recheck__hidden_without_change_permission(self, rf):
        user = User.objects.create_user(
            username="viewer",
            password="secret",
            is_staff=True,
        )
        user.user_permissions.add(
            Permission.objects.get(codename="view_domaincheck"),
        )
        request = rf.get("/admin/")
        request.user = user

        actions = admin.site._registry[DomainCheck].get_actions(request)

        assert "recheck" not in actions

    @pytest.mark.django_db
    def test_recheck__queues_a_fresh_check(self, client, admin_user, task_results):
        domain_check = DomainCheck.objects.create(
            name="example.com",
            status=DomainCheck.Status.COMPLETE,
            checks=[{"key": "mx"}],
        )
        client.force_login(admin_user)

        response = client.post(
            reverse("admin:domains_domaincheck_changelist"),
            {"action": "recheck", "_selected_action": [domain_check.pk]},
        )

        assert response.status_code == 302
        domain_check.refresh_from_db()
        assert domain_check.status == DomainCheck.Status.PENDING
        assert domain_check.checks == []
        assert [result.kwargs for result in task_results] == [{"name": "example.com"}]

    @pytest.mark.django_db
    def test_recheck__skips_domains_already_checking(
        self, client, admin_user, task_results
    ):
        running = DomainCheck.objects.create(
            name="running.example",
            status=DomainCheck.Status.RUNNING,
        )
        pending = DomainCheck.objects.create(
            name="pending.example",
            status=DomainCheck.Status.PENDING,
        )
        client.force_login(admin_user)

        response = client.post(
            reverse("admin:domains_domaincheck_changelist"),
            {
                "action": "recheck",
                "_selected_action": [running.pk, pending.pk],
            },
        )

        assert response.status_code == 302
        running.refresh_from_db()
        pending.refresh_from_db()
        assert running.status == DomainCheck.Status.RUNNING
        assert pending.status == DomainCheck.Status.PENDING
        assert task_results == []

    @pytest.mark.django_db
    def test_delete_selected__deletes_domain_check(self, client, admin_user):
        domain_check = DomainCheck.objects.create(name="example.com")
        client.force_login(admin_user)

        response = client.post(
            reverse("admin:domains_domaincheck_changelist"),
            {
                "action": "delete_selected",
                "_selected_action": [domain_check.pk],
                "post": "yes",
            },
        )

        assert response.status_code == 302
        assert not DomainCheck.objects.filter(pk=domain_check.pk).exists()
