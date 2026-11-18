from django.urls import path
from django.views import generic

from . import views

app_name = "docs"

urlpatterns = [
    path("", views.DocsListView.as_view(), name="list"),
    path(
        "webhooks/",
        generic.RedirectView.as_view(pattern_name="docs:detail", permanent=True),
        {"slug": "receiving"},
    ),
    path(
        "encryption/",
        generic.RedirectView.as_view(pattern_name="docs:detail", permanent=True),
        {"slug": "security"},
    ),
    path(
        "reliability/",
        generic.RedirectView.as_view(pattern_name="docs:detail", permanent=True),
        {"slug": "deliverability"},
    ),
    path("<slug:slug>/", views.DocsDetailView.as_view(), name="detail"),
]
