import dataclasses
import typing
from collections.abc import Iterable
from importlib import resources

import yaml


class MailProvider(typing.TypedDict):
    name: str
    country_code: str
    country_name: str
    suffixes: list[str]


MAIL_PROVIDERS: list[MailProvider] = yaml.safe_load(
    resources.files(__package__)
    .joinpath("jurisdictions.yaml")
    .read_text(encoding="utf-8")
)


@dataclasses.dataclass(frozen=True, slots=True)
class JurisdictionFlag:
    country_code: str
    country_name: str
    sources: tuple[str, ...]

    @property
    def flag_url(self) -> str:
        return f"https://flagcdn.com/{self.country_code.lower()}.svg"


def match(
    exchange: str, providers: Iterable[MailProvider] = MAIL_PROVIDERS
) -> MailProvider | None:
    host = exchange.lower().rstrip(".")
    for provider in providers:
        if any(
            host == suffix or host.endswith(f".{suffix}")
            for suffix in provider["suffixes"]
        ):
            return provider
    return None


def get_country_name(country_code: str) -> str:
    for provider in MAIL_PROVIDERS:
        if provider["country_code"] == country_code:
            return provider["country_name"]
    return country_code
