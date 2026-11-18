import datetime as dt
from types import SimpleNamespace

import pytest
from django.utils import timezone

from domains.check.evaluation import Check
from domains.check.tasks import (
    CheckRetry,
    check_authentication,
    check_delivery,
    check_domain,
    check_reputation,
)
from domains.models import DomainCheck


class Queue:
    def __init__(self):
        self.calls = []

    def enqueue(self, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def queue(monkeypatch):
    tasks = SimpleNamespace(
        delivery=Queue(),
        authentication=Queue(),
        reputation=Queue(),
    )
    monkeypatch.setattr("domains.check.tasks.check_delivery", tasks.delivery)
    monkeypatch.setattr(
        "domains.check.tasks.check_authentication", tasks.authentication
    )
    monkeypatch.setattr("domains.check.tasks.check_reputation", tasks.reputation)
    return tasks


def make_check(**kwargs):
    fields = {
        "name": "example.com",
        "status": DomainCheck.Status.COMPLETE,
        "checks": [],
    }
    fields.update(kwargs)
    return DomainCheck.objects.create(**fields)


def make_context(attempt, name="example.com", error=ValueError):
    return SimpleNamespace(
        attempt=attempt,
        task_result=SimpleNamespace(
            errors=[SimpleNamespace(exception_class=error)],
            kwargs={"name": name},
        ),
    )


class TestCheckRetry:
    def test_call__returns_the_first_backoff(self):
        assert CheckRetry()(make_context(0)) == dt.timedelta(seconds=5)

    def test_call__doubles_the_backoff(self):
        assert CheckRetry()(make_context(1)) == dt.timedelta(seconds=10)

    @pytest.mark.django_db
    def test_call__fails_the_check_after_the_last_attempt(self):
        check = make_check(status=DomainCheck.Status.RUNNING)

        assert CheckRetry()(make_context(2)) is None

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.FAILED

    @pytest.mark.django_db
    def test_call__leaves_a_finished_check_untouched(self):
        check = make_check(status=DomainCheck.Status.COMPLETE)

        assert CheckRetry()(make_context(2)) is None

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.COMPLETE

    @pytest.mark.django_db
    def test_call__fails_on_an_unexpected_exception_too(self):
        check = make_check(status=DomainCheck.Status.RUNNING)

        assert CheckRetry()(make_context(2, error=KeyError)) is None

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.FAILED


@pytest.mark.django_db
class TestCheckDomain:
    def test_check_domain__starts_a_fresh_check(self, queue):
        check = make_check(status=DomainCheck.Status.COMPLETE, checks=[{"key": "mx"}])
        DomainCheck.objects.filter(pk=check.pk).update(
            modified_at=timezone.now() - dt.timedelta(days=2)
        )

        check_domain.func(name="example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.RUNNING
        assert check.checks == []
        assert queue.delivery.calls == [{"name": "example.com"}]
        assert queue.authentication.calls == [{"name": "example.com"}]
        assert queue.reputation.calls == [{"name": "example.com"}]

    def test_check_domain__leaves_a_fresh_check_alone(self, queue):
        check = make_check(status=DomainCheck.Status.COMPLETE)

        check_domain.func(name="example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.COMPLETE
        assert queue.delivery.calls == []
        assert queue.authentication.calls == []
        assert queue.reputation.calls == []


@pytest.mark.django_db
class TestCheckWorkers:
    def test_check_delivery__stores_the_delivery_checks(self, dns_resolver):
        check = make_check(status=DomainCheck.Status.RUNNING)

        check_delivery.func(name="example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.RUNNING
        assert [row["key"] for row in check.checks] == ["mx", "mta_sts", "tls_rpt"]

    def test_check_authentication__stores_the_authentication_checks(self, dns_resolver):
        check = make_check(status=DomainCheck.Status.RUNNING)

        check_authentication.func(name="example.com")

        check.refresh_from_db()
        assert [row["key"] for row in check.checks] == ["spf", "dmarc"]

    def test_check_reputation__stores_the_blocklist_check(self, dns_resolver):
        check = make_check(status=DomainCheck.Status.RUNNING)

        check_reputation.func(name="example.com")

        check.refresh_from_db()
        assert [row["key"] for row in check.checks] == ["blocklists"]

    def test_check_workers__complete_the_check(self, dns_resolver):
        check = make_check(status=DomainCheck.Status.RUNNING)

        check_delivery.func(name="example.com")
        check_authentication.func(name="example.com")
        check_reputation.func(name="example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.COMPLETE
        assert [row["key"] for row in check.checks] == list(Check.order())
