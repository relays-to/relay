from django import forms
from django.utils.translation import gettext_lazy as _

from abstract.forms import DomainInput
from domains.models import canonicalize_domain_name, validate_domain_name


class DomainCheckForm(forms.Form):
    INTERNAL_SUFFIXES = (
        ".local",
        ".internal",
        ".localhost",
        ".home.arpa",
        ".cluster.local",
        ".svc",
    )

    name = forms.CharField(
        label=_("domain"),
        max_length=255,
        validators=[validate_domain_name],
        widget=DomainInput({"input_group": "child"}),
    )

    def clean_name(self):
        name = canonicalize_domain_name(self.cleaned_data["name"])
        if name.endswith(self.INTERNAL_SUFFIXES):
            raise forms.ValidationError(
                _("Enter a public domain name, for example acme.com")
            )
        return name
