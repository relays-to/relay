import dataclasses
from collections.abc import Iterable

from django.utils.translation import gettext_lazy as _


@dataclasses.dataclass(frozen=True, slots=True)
class MailProvider:
    name: str
    country_code: str
    suffixes: tuple[str, ...]


MAIL_PROVIDERS: tuple[MailProvider, ...] = (
    MailProvider("Microsoft 365", "US", ("mail.protection.outlook.com", "outlook.com")),
    MailProvider(
        "Google Workspace", "US", ("smtp.google.com", "google.com", "googlemail.com")
    ),
    MailProvider("Amazon", "US", ("amazonaws.com", "awsapps.com")),
    MailProvider("Apple iCloud", "US", ("mail.icloud.com", "icloud.com")),
    MailProvider("Cloudflare Email Routing", "US", ("mx.cloudflare.net",)),
    MailProvider("Proofpoint", "US", ("pphosted.com",)),
    MailProvider("Barracuda", "US", ("barracudanetworks.com",)),
    MailProvider("Cisco", "US", ("iphmx.com",)),
    MailProvider("Mimecast", "GB", ("mimecast.com",)),
    MailProvider("Zoho", "IN", ("zoho.com", "zoho.eu", "zohomail.com")),
    MailProvider("Proton", "CH", ("protonmail.ch", "protonmail.com", "proton.me")),
    MailProvider("mailbox.org", "DE", ("mailbox.org",)),
    MailProvider(
        "IONOS",
        "DE",
        ("ionos.de", "ionos.com", "1and1.com", "kundenserver.de"),
    ),
    MailProvider("Hetzner", "DE", ("your-server.de", "hetzner.com")),
    MailProvider("OVHcloud", "FR", ("ovh.net", "ovh.com", "ovh.fr")),
    MailProvider("Scaleway", "FR", ("scaleway.com",)),
    MailProvider("Infomaniak", "CH", ("infomaniak.ch", "infomaniak.com")),
    MailProvider("Tuta", "DE", ("tutanota.de", "tutanota.com", "tuta.com")),
    MailProvider("Posteo", "DE", ("posteo.de",)),
    MailProvider("Fastmail", "AU", ("messagingengine.com", "fastmail.com")),
    MailProvider("Yandex", "RU", ("yandex.net", "yandex.ru", "yandex.com")),
    MailProvider("VK", "RU", ("mail.ru", "vk.com")),
    MailProvider("Alibaba Cloud", "CN", ("aliyun.com", "alibaba.com")),
    MailProvider("Tencent", "CN", ("qq.com", "tencent.com")),
    MailProvider("GoDaddy", "US", ("secureserver.net", "godaddy.com")),
    MailProvider("Rackspace", "US", ("emailsrvr.com",)),
    MailProvider("Gandi", "FR", ("gandi.net",)),
    MailProvider("Hornetsecurity", "DE", ("hornetsecurity.com",)),
    MailProvider("Retarus", "DE", ("retarus.com",)),
    MailProvider("Mailgun", "SE", ("mailgun.org",)),
    MailProvider("SendGrid", "US", ("sendgrid.net",)),
    MailProvider("Postmark", "US", ("postmarkapp.com",)),
)


COUNTRY_NAMES = {
    "US": _("United States"),
    "DE": _("Germany"),
    "CH": _("Switzerland"),
    "FR": _("France"),
    "GB": _("United Kingdom"),
    "IN": _("India"),
    "AU": _("Australia"),
    "RU": _("Russia"),
    "CN": _("China"),
    "SE": _("Sweden"),
    "NL": _("Netherlands"),
    "CA": _("Canada"),
    "JP": _("Japan"),
    "SG": _("Singapore"),
    "IE": _("Ireland"),
    "PL": _("Poland"),
    "ES": _("Spain"),
    "IT": _("Italy"),
    "AT": _("Austria"),
    "BE": _("Belgium"),
    "DK": _("Denmark"),
    "FI": _("Finland"),
    "NO": _("Norway"),
    "CZ": _("Czechia"),
    "UA": _("Ukraine"),
    "TR": _("T\u00fcrkiye"),
    "IL": _("Israel"),
    "AE": _("United Arab Emirates"),
    "HK": _("Hong Kong"),
    "KR": _("South Korea"),
    "ZA": _("South Africa"),
    "BR": _("Brazil"),
    "MX": _("Mexico"),
    "AR": _("Argentina"),
    "NZ": _("New Zealand"),
    "PT": _("Portugal"),
    "GR": _("Greece"),
    "RO": _("Romania"),
    "HU": _("Hungary"),
    "SK": _("Slovakia"),
    "SI": _("Slovenia"),
    "HR": _("Croatia"),
    "BG": _("Bulgaria"),
    "LT": _("Lithuania"),
    "LV": _("Latvia"),
    "EE": _("Estonia"),
    "LU": _("Luxembourg"),
    "IS": _("Iceland"),
    "LI": _("Liechtenstein"),
    "MT": _("Malta"),
    "CY": _("Cyprus"),
}


@dataclasses.dataclass(frozen=True, slots=True)
class JurisdictionFlag:
    country_code: str
    country_name: str
    sources: tuple[str, ...]

    @property
    def flag_url(self) -> str:
        return f"https://flagcdn.com/{self.country_code.lower()}.svg"

    @property
    def has_flag(self) -> bool:
        return self.country_code in COUNTRY_NAMES


def match(
    exchange: str, providers: Iterable[MailProvider] = MAIL_PROVIDERS
) -> MailProvider | None:
    host = exchange.lower().rstrip(".")
    best_provider = None
    best_suffix_length = 0
    for provider in providers:
        for suffix in provider.suffixes:
            suffix = suffix.lower().rstrip(".")
            if host == suffix or host.endswith(f".{suffix}"):
                length = len(suffix)
                if length > best_suffix_length:
                    best_provider = provider
                    best_suffix_length = length
    return best_provider


def get_country_name(country_code: str):
    return COUNTRY_NAMES.get(country_code, country_code)
