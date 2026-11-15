from abstract.forms import DomainInput


class TestDomainInput:
    def test_default_attrs(self):
        assert DomainInput().attrs == DomainInput.DEFAULT_ATTRS

    def test_merges_and_overrides_attrs(self):
        widget = DomainInput({"placeholder": "acme.com", "input_group": "child"})

        assert widget.attrs["placeholder"] == "acme.com"
        assert widget.attrs["input_group"] == "child"
        assert widget.attrs["autocomplete"] == "off"

    def test_keeps_default_attrs_without_overrides(self):
        assert DomainInput(None).attrs["inputmode"] == "url"
