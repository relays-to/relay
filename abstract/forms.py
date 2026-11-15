from django import forms


class DomainInput(forms.TextInput):
    """Text input tuned for typing a bare domain name."""

    default_attrs = {
        "placeholder": "example.com",
        "autocomplete": "off",
        "autocorrect": "off",
        "autocapitalize": "none",
        "spellcheck": "false",
        "inputmode": "url",
    }

    def __init__(self, attrs=None):
        super().__init__({**self.default_attrs, **(attrs or {})})
