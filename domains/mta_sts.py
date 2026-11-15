"""Pure MTA-STS record helpers shared by verification and the public check."""

import re

MTA_STS_EXTENSION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
MTA_STS_EXTENSION_VALUE = re.compile(r"[\x21-\x3A\x3C\x3E-\x7E]+")


def parse_mta_sts_txt_record(value):
    """Return valid MTA-STS tags, or `None` for a malformed record."""
    fields = value.split(";")
    if fields[0] != "v=STSv1":
        return None
    if fields[-1].strip(" \t") == "":
        fields.pop()

    tags = {}
    for field in fields[1:]:
        field = field.strip(" \t")
        if "=" not in field:
            return None
        name, tag_value = field.split("=", 1)
        if name in tags:
            return None
        if name == "id":
            if re.fullmatch(r"[A-Za-z0-9]{1,32}", tag_value) is None:
                return None
        elif (
            MTA_STS_EXTENSION_NAME.fullmatch(name) is None
            or MTA_STS_EXTENSION_VALUE.fullmatch(tag_value) is None
        ):
            return None
        tags[name] = tag_value
    return tags if "id" in tags else None


def matches_mta_sts_mx_pattern(hostname, pattern):
    """Return whether an MX hostname matches an MTA-STS mx pattern."""
    hostname = hostname.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()
    if pattern.startswith("*."):
        label, _, suffix = hostname.partition(".")
        matches = bool(label) and suffix == pattern.removeprefix("*.")
    else:
        matches = hostname == pattern
    return matches
