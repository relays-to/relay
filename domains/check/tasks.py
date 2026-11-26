import dataclasses
import datetime as dt
import logging

from crontask import cron
from django.conf import settings
from django.core.mail import mailers
from django.db.models import Q
from django.tasks import DEFAULT_TASK_QUEUE_NAME, TaskContext, task
from django.utils import timezone
from threadmill.retry import ExponentialBackoff

from accounts.models import Membership
from domains.emails import DomainMonitorEmail, domain_monitor_notification
from domains.models import Domain, DomainCheck

from .evaluation import (
    BlocklistsCheck,
    DmarcCheck,
    MtaStsCheck,
    MxCheck,
    SpfCheck,
    TlsRptCheck,
)
from .lookup import Lookup

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class CheckRetry(ExponentialBackoff):
    """Retry a check twice, five seconds apart, then fail the row."""

    base_delay: dt.timedelta = dt.timedelta(seconds=5)
    max_retries: int = 2

    def __call__(self, context: TaskContext) -> dt.timedelta | None:
        if delay := super().__call__(context):
            return delay
        DomainCheck.objects.filter(
            name=context.task_result.kwargs["name"],
            status=DomainCheck.Status.RUNNING,
        ).update(
            status=DomainCheck.Status.FAILED,
            modified_at=timezone.now(),
        )
        return None


@task(queue_name=DEFAULT_TASK_QUEUE_NAME)
def send_domain_check_changes(
    domain_name: str, domain_pk: int | None, changes: list[dict]
) -> None:
    try:
        domain = Domain.objects.select_related("org", "domain_check").get(
            pk=domain_pk,
            domain_check__name=domain_name,
            org__suspended_at__isnull=True,
        )
    except Domain.DoesNotExist:
        logger.info(
            "Dropped the domain monitor mail for %r, the domain is missing or suspended",
            domain_name,
        )
    else:
        with mailers.default as mailer:
            for membership in (
                Membership.objects.filter(org=domain.org)
                .for_notification(domain_monitor_notification)
                .select_related("user")
            ):
                try:
                    mailer.send_messages(
                        [
                            DomainMonitorEmail.to_user(
                                membership.user,
                                domain=domain,
                                domain_check=domain.domain_check,
                                changes=changes,
                                language=settings.LANGUAGE_CODE,
                            )
                        ]
                    )
                except OSError, ValueError:
                    logger.warning(
                        "Domain monitor mail for user %r failed",
                        membership.user,
                        exc_info=True,
                    )


def enqueue_changes(domain_name: str, changes: list[dict]) -> None:
    try:
        domain_pk = Domain.objects.get(domain_check__name=domain_name).pk
    except Domain.DoesNotExist:
        logger.info(
            "Dropped the domain monitor mail for %r, the domain is missing",
            domain_name,
        )
    else:
        send_domain_check_changes.enqueue(
            domain_name=domain_name, domain_pk=domain_pk, changes=changes
        )


@cron("*/5 * * * *")
@task(queue_name=DEFAULT_TASK_QUEUE_NAME)
def monitor_domains() -> None:
    now = timezone.now()
    stale_checks = (
        DomainCheck.objects.filter(
            domain__isnull=False,
            domain__is_managed=False,
            domain__org__suspended_at__isnull=True,
        )
        .filter(
            Q(status=DomainCheck.Status.PENDING)
            | Q(modified_at__lt=now - DomainCheck.MONITOR_INTERVAL)
        )
        .order_by("modified_at")
    )
    domain_names = list(stale_checks.values_list("name", flat=True))
    DomainCheck.objects.filter(name__in=domain_names).update(
        status=DomainCheck.Status.PENDING, modified_at=now
    )
    for domain_name in domain_names:
        check_domain.enqueue(name=domain_name)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_delivery(name: str) -> None:
    lookup = Lookup()
    if changes := DomainCheck.store(
        name, [check.run(name, lookup) for check in (MxCheck, MtaStsCheck, TlsRptCheck)]
    ):
        enqueue_changes(name, changes)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_authentication(name: str) -> None:
    lookup = Lookup()
    if changes := DomainCheck.store(
        name, [check.run(name, lookup) for check in (SpfCheck, DmarcCheck)]
    ):
        enqueue_changes(name, changes)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_reputation(name: str) -> None:
    if changes := DomainCheck.store(name, [BlocklistsCheck.run(name, Lookup())]):
        enqueue_changes(name, changes)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME)
def check_domain(name: str) -> None:
    domain_check = DomainCheck.objects.get(name=name)
    is_fresh = (
        domain_check.status == DomainCheck.Status.COMPLETE and not domain_check.is_stale
    )
    if not is_fresh:
        DomainCheck.objects.filter(pk=domain_check.pk).update(
            status=DomainCheck.Status.RUNNING,
            checks=[],
            modified_at=timezone.now(),
        )
        check_delivery.enqueue(name=name)
        check_authentication.enqueue(name=name)
        check_reputation.enqueue(name=name)


def enqueue_check(domain_name: str, *, restart: bool = False) -> None:
    queryset = DomainCheck.objects.filter(name=domain_name)
    fields = {
        "status": DomainCheck.Status.PENDING,
        "modified_at": timezone.now(),
    }
    if restart:
        queryset = queryset.exclude(
            status__in={DomainCheck.Status.PENDING, DomainCheck.Status.RUNNING}
        )
        fields["checks"] = []
    if queryset.update(**fields):
        check_domain.enqueue(name=domain_name)
