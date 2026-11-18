import datetime as dt
import secrets

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.http import urlencode
from django.utils.translation import gettext_lazy as _
from django.views import generic

from abstract.views import (
    BreadcrumbViewMixin,
    CacheControlMixin,
    ConditionalGetListMixin,
    ConditionalGetMixin,
    NoStoreCacheMixin,
)
from domains.models import DomainCheck, canonicalize_domain_name

from .forms import DomainCheckForm
from .open_graph import DomainCheckImage
from .tasks import check_domain


class DomainCheckListView(
    ConditionalGetListMixin, BreadcrumbViewMixin, generic.ListView
):
    model = DomainCheck
    title = _("Domain check")
    parent = "home"
    paginate_by = 50

    def get_template_names(self):
        return ["domain_check/domaincheck_list.html"]

    def get_queryset(self):
        return super().get_queryset().order_by("penalty", "-modified_at")

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {
            "form": DomainCheckForm(initial={"name": self.request.GET.get("name", "")})
        }


class DomainCheckSubmitView(NoStoreCacheMixin, generic.FormView):
    form_class = DomainCheckForm

    def get(self, request, *args, **kwargs):
        return redirect("domain_check:list")

    def form_valid(self, form):
        domain_check, _created = DomainCheck.objects.get_or_create(
            name=form.cleaned_data["name"]
        )
        if domain_check.is_stale:
            check_domain.enqueue(name=domain_check.name)
        else:
            messages.info(
                self.request,
                _("This domain was checked less than a day ago."),
            )
        return redirect(domain_check)

    def form_invalid(self, form):
        for error in form.errors.get("name", []):
            messages.error(self.request, error)
        return redirect("domain_check:list")


class DomainCheckDetailView(
    ConditionalGetMixin, BreadcrumbViewMixin, generic.DetailView
):
    model = DomainCheck
    context_object_name = "domain_check"
    parent = "domain_check:list"
    # Poll while a check runs, spread out so a burst of visitors does not
    # reload in lockstep.
    REFRESH_INTERVAL = dt.timedelta(seconds=2)
    REFRESH_JITTER = dt.timedelta(seconds=2)

    def get(self, request, *args, **kwargs):
        try:
            name = canonicalize_domain_name(self.kwargs["name"])
        except ValidationError:
            return self.redirect_to_list(self.kwargs["name"])
        if name != self.kwargs["name"]:
            return redirect("domain_check:detail", name=name)
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            return self.redirect_to_list(name)

    def redirect_to_list(self, name):
        """Send the visitor to the list with the check form prefilled."""
        return redirect(f"{reverse('domain_check:list')}?{urlencode({'name': name})}")

    def get_object(self, queryset=None):
        return get_object_or_404(DomainCheck, name=self.kwargs["name"])

    @method_decorator(login_required)
    def post(self, request, *args, **kwargs):
        """Queue a fresh check and drop the visitor on the polling page."""
        domain_check = self.get_object()
        if domain_check.status not in {
            DomainCheck.Status.PENDING,
            DomainCheck.Status.RUNNING,
        }:
            DomainCheck.objects.filter(pk=domain_check.pk).update(
                status=DomainCheck.Status.RUNNING,
                checks=[],
                modified_at=timezone.now(),
            )
            check_domain.enqueue(name=domain_check.name)
        return redirect("domain_check:detail", name=domain_check.name)

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {
            "refresh_secs": (
                self.REFRESH_INTERVAL.total_seconds()
                + secrets.randbelow(int(self.REFRESH_JITTER.total_seconds()) + 1)
            )
        }

    def get_template_names(self):
        if self.object.status in {
            DomainCheck.Status.PENDING,
            DomainCheck.Status.RUNNING,
        }:
            return ["domain_check/domaincheck_checking.html"]
        return ["domain_check/domaincheck_detail.html"]


class DomainCheckOgImageView(CacheControlMixin, generic.View):
    """Render the share card for one domain check as a PNG."""

    OG_TTL = dt.timedelta(hours=6)
    cache_control = {
        "public": True,
        # The rendered bytes live in the Django cache for OG_TTL, so the
        # HTTP cache only needs to absorb request peaks.
        "max_age": dt.timedelta(minutes=1),
        "s_maxage": dt.timedelta(minutes=5),
    }

    def get(self, request, name, *args, **kwargs):
        try:
            name = canonicalize_domain_name(name)
        except ValidationError as error:
            raise Http404 from error
        check = get_object_or_404(DomainCheck, name=name)
        host = request.get_host()
        image = DomainCheckImage(
            check=check,
            host=host,
            cache_key=(
                f"domain_check:open_graph:{name}:{host}:"
                f"{int(check.modified_at.timestamp())}"
            ),
            cache_ttl=self.OG_TTL,
        ).render()
        return HttpResponse(image, content_type="image/png")
