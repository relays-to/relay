import pytest

from abstract.forms import DomainInput
from domains.check.forms import DomainCheckForm


class TestDomainCheckForm:
    def test_clean_name__canonicalizes_the_name(self):
        form = DomainCheckForm({"name": "Example.COM"})

        assert form.is_valid()
        assert form.cleaned_data["name"] == "example.com"

    def test_clean_name__accepts_an_idn(self):
        form = DomainCheckForm({"name": "münich.com"})

        assert form.is_valid()
        assert form.cleaned_data["name"] == "xn--mnich-kva.com"

    @pytest.mark.parametrize(
        "name",
        [
            "printer.local",
            "db.internal",
            "app.localhost",
            "router.home.arpa",
            "pod.cluster.local",
            "svc.cluster.local",
            "api.svc",
        ],
    )
    def test_clean_name__rejects_an_internal_suffix(self, name):
        form = DomainCheckForm({"name": name})

        assert not form.is_valid()
        assert form.errors["name"] == [
            "Enter a public domain name, for example acme.com"
        ]

    def test_clean_name__rejects_an_invalid_domain(self):
        form = DomainCheckForm({"name": "-example.com"})

        assert not form.is_valid()

    def test_name__uses_the_domain_widget(self):
        assert type(DomainCheckForm().fields["name"].widget) is DomainInput
