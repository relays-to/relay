import pytest
from django.contrib import admin
from django.urls import reverse

from domains.admin import DomainAdmin, DomainCheckAdmin
from domains.models import Domain, DomainCheck


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
