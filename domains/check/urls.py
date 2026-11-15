from django.urls import path

from . import views

app_name = "domain_check"

# An `include()` cannot group the `<str:name>` patterns: routes concatenate
# literally, so the image would need a leading "/" (urls.W002) or the detail
# page a trailing slash.
urlpatterns = [
    path("", views.DomainCheckListView.as_view(), name="list"),
    path("<str:name>/og.png", views.DomainCheckOgImageView.as_view(), name="og-image"),
    path("<str:name>", views.DomainCheckDetailView.as_view(), name="detail"),
]
