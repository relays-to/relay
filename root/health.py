import asyncio
import dataclasses
import datetime as dt
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver
from django.conf import settings
from django.urls import path
from health_check.base import HealthCheck
from health_check.exceptions import ServiceUnavailable, ServiceWarning
from health_check.views import HealthCheckView
from redis.asyncio import Redis

from abstract.blocklists import (
    DEFAULT_ADDRESS_PROVIDERS,
    REFUSAL_NETWORK,
    BlocklistProvider,
    reverse_pointer,
)


class BlocklistListing(ServiceUnavailable):
    def __init__(self, address, provider, codes):
        self.address = address
        self.provider = provider
        self.codes = codes
        reasons = ", ".join(
            dict.fromkeys(
                provider.reasons[code] for code in codes if code in provider.reasons
            )
        )
        message = f"Listed on {provider.name} ({provider.zone})"
        if reasons:
            message = f"{message}: {reasons}"
        super().__init__(message)


class BlocklistLookupError(ServiceWarning):
    failure_reasons = frozendict(
        {
            "LifetimeTimeout": "the provider did not answer in time",
            "NoNameservers": "no nameserver answered for the provider",
        }
    )

    def __init__(self, address, provider, error):
        self.address = address
        self.provider = provider
        reason = self.failure_reasons.get(type(error).__name__, type(error).__name__)
        super().__init__(f"{provider.name} ({provider.zone}) lookup failed: {reason}")


class BlocklistRefusal(ServiceWarning):
    query_error_reasons = frozendict(
        {
            "127.255.255.252": "the query name is invalid",
            "127.255.255.253": "the provider rejected the query from this resolver",
            "127.255.255.254": "the provider rejected the query from this resolver",
            "127.255.255.255": "the provider blocked this resolver",
        }
    )

    def __init__(self, address, provider, codes):
        self.address = address
        self.provider = provider
        reasons = ", ".join(
            dict.fromkeys(
                self.query_error_reasons.get(
                    code, "check the DNS resolver configuration"
                )
                for code in codes
            )
        )
        super().__init__(
            f"{provider.name} ({provider.zone}) refused the lookup: {reasons}"
        )


class BlocklistWarning(ServiceWarning):
    def __init__(self, address, message):
        self.address = address
        super().__init__(message)


class BlocklistAddressError(ServiceUnavailable):
    def __init__(self, address):
        self.address = address
        super().__init__(f"{address} is not an IP address")


@dataclasses.dataclass
class DnsBlocklist(HealthCheck):
    timeout = dt.timedelta(seconds=10)

    address: str
    providers: tuple[BlocklistProvider, ...] = dataclasses.field(
        default=DEFAULT_ADDRESS_PROVIDERS, repr=False
    )

    async def run(self):
        try:
            reversed_address = reverse_pointer(self.address)
        except ValueError as error:
            raise BlocklistAddressError(self.address) from error
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self.timeout.total_seconds()
        results = await asyncio.gather(
            *(
                self.lookup(provider, reversed_address, resolver)
                for provider in self.providers
            )
        )
        issues = [result for result in results if result]
        if issues:
            message = "\n".join(issue.message for issue in issues)
            if any(isinstance(issue, ServiceUnavailable) for issue in issues):
                raise ServiceUnavailable(message)
            raise BlocklistWarning(self.address, message)

    async def lookup(self, provider, reversed_address, resolver):
        zone = provider.zone
        if provider.keyed_zone and settings.SPAMHAUS_KEY:
            zone = provider.keyed_zone.format(key=settings.SPAMHAUS_KEY)
        query = f"{reversed_address}.{zone}"
        issue = None
        try:
            answers = await resolver.resolve(query, "A")
        except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
            answers = ()
        except dns.exception.DNSException as error:
            issue = BlocklistLookupError(self.address, provider, error)
            answers = ()
        codes = sorted(
            (rdata.address for rdata in answers),
            key=ipaddress.ip_address,
        )
        if issue is None:
            errors = [
                code for code in codes if ipaddress.ip_address(code) in REFUSAL_NETWORK
            ]
            if errors:
                issue = BlocklistRefusal(self.address, provider, errors)
            elif codes:
                issue = BlocklistListing(self.address, provider, codes)
        return issue


class ReputationHealthCheckView(HealthCheckView):
    """Answer 200 when every check only warned, 500 when any is unavailable."""

    async def get(self, request, *args, **kwargs):
        response = await super().get(request, *args, **kwargs)
        if response.status_code == 500 and all(
            error is None or isinstance(error, ServiceWarning)
            for error in (result.error for result in self.results)
        ):
            response.status_code = 200
        return response


reputation_checks = [
    (DnsBlocklist, {"address": address}) for address in settings.SMTP_SOURCE_IPS
]

node_checks = [
    "health_check.contrib.psutil.Disk",
    "health_check.contrib.psutil.Memory",
]

application_checks = [
    "health_check.Database",
    "health_check.Cache",
    (
        "health_check.contrib.redis.Redis",
        {"client_factory": lambda: Redis.from_url(settings.REDIS_URL)},
    ),
    (
        "health_check.contrib.redis.Redis",
        {"client_factory": lambda: Redis.from_url(settings.TASK_REDIS_URL)},
    ),
    *(
        ("health_check.contrib.threadmill.Threadmill", {"queue_name": queue_name})
        for queue_name in settings.TASK_QUEUES
    ),
    "health_check.contrib.crontask.Scheduler",
    "health_check.Storage",
    "health_check.Mail",
    (
        "health_check.DNS",
        {"hostname": "mail.relay.open.relays.to", "record_type": "MX"},
    ),
    (
        "health_check.RemoteCheck",
        {
            "url": f"{settings.PLATFORM_URL}/health/reputation/",
            "label": "Reputation",
            "timeout": dt.timedelta(seconds=15),
        },
    ),
]

pipeline_checks = [
    "health_check.contrib.rss.Hetzner",
    "health_check.contrib.rss.GoogleCloud",  # distroless images
    # CI, the image registry, the source checkout, and the API the runner
    # talks to.
    ("health_check.contrib.atlassian.GitHub", {"component": "Actions"}),
    ("health_check.contrib.atlassian.GitHub", {"component": "Packages"}),
    ("health_check.contrib.atlassian.GitHub", {"component": "Git Operations"}),
    ("health_check.contrib.atlassian.GitHub", {"component": "API Requests"}),
    ("health_check.contrib.atlassian.Sentry", {"component": "EU Ingestion"}),
    ("health_check.contrib.atlassian.Sentry", {"component": "API"}),
    "health_check.contrib.atlassian.Npm",
    "health_check.contrib.atlassian.PyPI",
]

urlpatterns = [
    path(
        "node/",
        HealthCheckView.as_view(checks=node_checks, allow_anonymous=True),
        name="health-node",
    ),
    path(
        "application/",
        HealthCheckView.as_view(
            checks=application_checks,
            max_age=dt.timedelta(seconds=30),
            allow_anonymous=True,
        ),
        name="health-application",
    ),
    path(
        "reputation/",
        ReputationHealthCheckView.as_view(
            checks=reputation_checks,
            max_age=dt.timedelta(seconds=30),
            allow_anonymous=True,
        ),
        name="health-reputation",
    ),
    path(
        "pipeline/",
        HealthCheckView.as_view(
            checks=pipeline_checks,
            max_age=dt.timedelta(seconds=30),
            allow_anonymous=True,
        ),
        name="health-pipeline",
    ),
]
