import dataclasses
import datetime
from collections.abc import Iterable

from django.db import transaction
from django.tasks import DEFAULT_TASK_QUEUE_NAME, TaskContext, task
from django.utils import timezone
from threadmill.retry import ExponentialBackoff

from domains.models import DomainCheck

from .evaluation import (
    CHECK_ORDER,
    CheckResult,
    evaluate_authentication,
    evaluate_delivery,
    evaluate_reputation,
)
from .lookup import Lookup
from .tiers import penalty_for


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class CheckRetry(ExponentialBackoff):
    """Retry a check twice, five seconds apart, then fail the row."""

    base_delay: datetime.timedelta = datetime.timedelta(seconds=5)
    max_retries: int = 2

    def __call__(self, context: TaskContext) -> datetime.timedelta | None:
        """Return the wait before the next attempt, or mark the row failed on the last."""
        delay = super().__call__(context)
        if delay is not None:
            return delay
        DomainCheck.objects.filter(
            name=context.task_result.kwargs["name"],
            status=DomainCheck.Status.RUNNING,
        ).update(
            status=DomainCheck.Status.FAILED,
            modified_at=timezone.now(),
        )
        return None


def store_results(name: str, results: Iterable[CheckResult]) -> None:
    """Merge the results into the stored checks and complete the row once all are in."""
    with transaction.atomic():
        domain_check = DomainCheck.objects.select_for_update().get(name=name)
        if domain_check.status == DomainCheck.Status.RUNNING:
            merged = {check["key"]: check for check in domain_check.checks} | {
                result.key: dataclasses.asdict(result) | {"status": result.status}
                for result in results
            }
            checks = [merged[key] for key in CHECK_ORDER if key in merged]
            update_fields = ["checks"]
            if len(checks) == len(CHECK_ORDER):
                domain_check.penalty = penalty_for(
                    *check.get("subchecks", []) for check in checks
                )
                domain_check.status = DomainCheck.Status.COMPLETE
                domain_check.checked_at = timezone.now()
                update_fields += ["penalty", "status", "checked_at"]
            domain_check.checks = checks
            domain_check.save(update_fields=update_fields)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_delivery(name: str) -> None:
    """Evaluate the delivery checks and store them on the row."""
    results = evaluate_delivery(name, Lookup())
    store_results(name, results)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_authentication(name: str) -> None:
    """Evaluate the authentication checks and store them on the row."""
    results = evaluate_authentication(name, Lookup())
    store_results(name, results)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=CheckRetry())
def check_reputation(name: str) -> None:
    """Evaluate the reputation checks and store them on the row."""
    results = evaluate_reputation(name, Lookup())
    store_results(name, results)


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
