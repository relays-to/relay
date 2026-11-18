from django.contrib import admin, messages
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from abstract.admin import TimeStampedAdminMixin

from .check.tasks import check_domain
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
    actions = ["recheck"]

    def has_add_permission(self, request):
        """Rows come from the public checker, which also queues the check."""
        return False

    @admin.action(description=_("Recheck selected domains"))
    def recheck(self, request, queryset):
        """Force a fresh check, even for results that are still recent."""
        to_check = queryset.exclude(
            status__in=[DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING]
        )
        names = list(to_check.values_list("name", flat=True))
        to_check.update(
            status=DomainCheck.Status.RUNNING,
            checks=[],
            modified_at=timezone.now(),
        )
        for name in names:
            check_domain.enqueue(name=name)
        if names:
            self.message_user(
                request,
                ngettext(
                    "%(count)d domain queued for a recheck.",
                    "%(count)d domains queued for a recheck.",
                    len(names),
                )
                % {"count": len(names)},
                messages.SUCCESS,
            )
