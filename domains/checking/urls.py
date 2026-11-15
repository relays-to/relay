from django.urls import path

from . import views

app_name = "domain_check"

urlpatterns = [
    path("", views.DomainCheckListView.as_view(), name="list"),
    path("<str:name>/og.png", views.DomainCheckOgImageView.as_view(), name="og-image"),
    path("<str:name>", views.DomainCheckDetailView.as_view(), name="detail"),
]
