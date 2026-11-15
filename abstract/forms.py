from django import forms


class DomainInput(forms.TextInput):
    """Text input tuned for typing a bare domain name."""

    DEFAULT_ATTRS = {
        "placeholder": "example.com",
        "autocomplete": "off",
        "autocorrect": "off",
        "autocapitalize": "none",
        "spellcheck": "false",
        "inputmode": "url",
    }

    def __init__(self, attrs=None):
        super().__init__({**self.DEFAULT_ATTRS, **(attrs or {})})
