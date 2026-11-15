from django.urls import include, path

from . import views

app_name = "domain_check"

urlpatterns = [
    path("", views.DomainCheckListView.as_view(), name="list"),
    path("submit", views.DomainCheckSubmitView.as_view(), name="submit"),
    path(
        "<str:name>/",
        include(
            [
                path("", views.DomainCheckDetailView.as_view(), name="detail"),
                path("og.png", views.DomainCheckOgImageView.as_view(), name="og-image"),
            ]
        ),
    ),
]
