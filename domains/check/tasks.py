import dataclasses
import datetime

from django.tasks import DEFAULT_TASK_QUEUE_NAME, TaskContext, task
from django.utils import timezone
from threadmill.retry import ExponentialBackoff

from domains.models import DomainCheck

from .evaluation import (
    BlocklistsCheck,
    DmarcCheck,
    MtaStsCheck,
    MxCheck,
    SpfCheck,
    TlsRptCheck,
)
from .lookup import Lookup


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class CheckRetry(ExponentialBackoff):
    """Retry a check twice, five seconds apart, then fail the row."""

    base_delay: datetime.timedelta = datetime.timedelta(seconds=5)
    max_retries: int = 2

    def __call__(self, context: TaskContext) -> datetime.timedelta | None:
        """Return the next delay, or fail the row once the retries run out."""
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


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_delivery(name: str) -> None:
    """Grade how the domain receives mail and store the results."""
    lookup = Lookup()
    DomainCheck.store(
        name, [check.run(name, lookup) for check in (MxCheck, MtaStsCheck, TlsRptCheck)]
    )


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_authentication(name: str) -> None:
    """Grade the domain's authentication records and store the results."""
    lookup = Lookup()
    DomainCheck.store(
        name, [check.run(name, lookup) for check in (SpfCheck, DmarcCheck)]
    )


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_reputation(name: str) -> None:
    """Grade the domain against the blocklists and store the result."""
    DomainCheck.store(name, [BlocklistsCheck.run(name, Lookup())])


@task(queue_name=DEFAULT_TASK_QUEUE_NAME)
def check_domain(name: str) -> None:
    """Queue every check group for a domain that is due."""
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
