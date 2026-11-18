from django.contrib import admin

from abstract.admin import TimeStampedAdminMixin

from .models import Domain, DomainCheck


@admin.register(Domain)
class DomainAdmin(TimeStampedAdminMixin, admin.ModelAdmin):
    list_display = [
        "name",
        "org",
        "verified_at",
        "nameserver_status",
        "spf_status",
        "dkim_rsa2048_status",
        "dkim_ed25519_status",
        "dmarc_status",
        "created_at",
    ]
    list_filter = [
        "nameserver_status",
        "spf_status",
        "dkim_rsa2048_status",
        "dkim_ed25519_status",
        "dmarc_status",
        "verified_at",
    ]
    search_fields = ["name", "org__slug"]
    autocomplete_fields = ["org", "dkim_key_rsa2048", "dkim_key_ed25519"]


@admin.register(DomainCheck)
class DomainCheckAdmin(TimeStampedAdminMixin, admin.ModelAdmin):
    list_display = [
        "name",
        "status",
        "penalty",
        "modified_at",
        "created_at",
    ]
    list_filter = ["status"]
    search_fields = ["name"]
    readonly_fields = ["name", "status", "penalty", "checks"]

    def has_add_permission(self, request):
        """Rows come from the public checker, which also queues the check."""
        return False
