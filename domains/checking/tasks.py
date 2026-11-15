import dataclasses
import datetime

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

CHECK_RETRY = ExponentialBackoff(
    base_delay=datetime.timedelta(seconds=5),
    max_retries=2,
)


def check_retry(context: TaskContext) -> datetime.timedelta | None:
    if delay := CHECK_RETRY(context):
        return delay
    DomainCheck.objects.filter(
        name=context.task_result.kwargs["name"],
        status=DomainCheck.Status.RUNNING,
    ).update(
        status=DomainCheck.Status.FAILED,
        modified_at=timezone.now(),
    )
    return None


def store_results(name: str, results: list[CheckResult]) -> None:
    with transaction.atomic():
        domain_check = DomainCheck.objects.select_for_update().get(name=name)
        if domain_check.status == DomainCheck.Status.RUNNING:
            merged = {check["key"]: check for check in domain_check.checks}
            merged.update(
                {
                    result.key: dataclasses.asdict(result) | {"status": result.status}
                    for result in results
                }
            )
            checks = [merged[key] for key in CHECK_ORDER if key in merged]
            update_fields = ["checks"]
            if all(key in merged for key in CHECK_ORDER):
                domain_check.penalty = penalty_for(
                    *check.get("subchecks", []) for check in checks
                )
                domain_check.status = DomainCheck.Status.COMPLETE
                domain_check.checked_at = timezone.now()
                update_fields += ["penalty", "status", "checked_at"]
            domain_check.checks = checks
            domain_check.save(update_fields=update_fields)


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=check_retry)
def check_delivery(name: str) -> None:
    store_results(name, evaluate_delivery(name, Lookup()))


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=check_retry)
def check_authentication(name: str) -> None:
    store_results(name, evaluate_authentication(name, Lookup()))


@task(queue_name=DEFAULT_TASK_QUEUE_NAME, retry=check_retry)
def check_reputation(name: str) -> None:
    store_results(name, evaluate_reputation(name, Lookup()))


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
