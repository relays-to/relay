import dataclasses
from collections.abc import Iterable
from importlib import resources

import yaml


@dataclasses.dataclass(frozen=True, slots=True)
class MailProvider:
    name: str
    country_code: str
    country_name: str
    suffixes: tuple[str, ...]


def load_mail_providers() -> tuple[MailProvider, ...]:
    data = yaml.safe_load(
        resources.files(__package__)
        .joinpath("jurisdictions.yaml")
        .read_text(encoding="utf-8")
    )
    return tuple(
        MailProvider(
            name=entry["name"],
            country_code=entry["country_code"],
            country_name=entry["country_name"],
            suffixes=tuple(suffix.lower().rstrip(".") for suffix in entry["suffixes"]),
        )
        for entry in data
    )


MAIL_PROVIDERS = load_mail_providers()


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
        return (
            len(self.country_code) == 2
            and self.country_code.isalpha()
            and self.country_code not in {"AP", "ZZ"}
        )


def match(
    exchange: str, providers: Iterable[MailProvider] = MAIL_PROVIDERS
) -> MailProvider | None:
    host = exchange.lower().rstrip(".")
    for provider in providers:
        if any(
            host == suffix or host.endswith(f".{suffix}")
            for suffix in provider.suffixes
        ):
            return provider
    return None


def get_country_name(country_code: str) -> str:
    for provider in MAIL_PROVIDERS:
        if provider.country_code == country_code:
            return provider.country_name
    return country_code
