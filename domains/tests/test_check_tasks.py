import copy
import datetime as dt
import logging
from types import SimpleNamespace

import pytest
from django.utils import timezone

from accounts.models import Membership
from domains.check.evaluation import Check
from domains.check.tasks import (
    CheckRetry,
    check_authentication,
    check_delivery,
    check_domain,
    check_reputation,
    enqueue_changes,
    enqueue_check,
    monitor_domains,
    send_domain_check_changes,
)
from domains.models import Domain, DomainCheck


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


@pytest.fixture
def domain_queue(monkeypatch):
    stub = Queue()
    monkeypatch.setattr("domains.check.tasks.check_domain", stub)
    return stub


@pytest.fixture
def mail_queue(monkeypatch):
    stub = Queue()
    monkeypatch.setattr("domains.check.tasks.send_domain_check_changes", stub)
    return stub


def make_monitored(org, name="example.com", **fields):
    Domain.objects.create(name=name, org=org)
    updates = {"status": DomainCheck.Status.COMPLETE, "checks": []}
    updates.update(fields)
    DomainCheck.objects.filter(name=name).update(**updates)
    return DomainCheck.objects.get(name=name)


def backdate(check, **delta):
    DomainCheck.objects.filter(pk=check.pk).update(
        modified_at=timezone.now() - dt.timedelta(**delta)
    )
    return DomainCheck.objects.get(pk=check.pk)


@pytest.mark.django_db
class TestMonitorDomains:
    def test_monitor_domains__queues_every_stale_check(self, org, domain_queue):
        stale = backdate(make_monitored(org), hours=2)
        pending = make_monitored(
            org, name="pending.example", status=DomainCheck.Status.PENDING
        )

        monitor_domains.func()

        assert domain_queue.calls == [
            {"name": "example.com"},
            {"name": "pending.example"},
        ]
        assert DomainCheck.objects.get(pk=stale.pk).status == DomainCheck.Status.PENDING
        assert (
            DomainCheck.objects.get(pk=pending.pk).status == DomainCheck.Status.PENDING
        )

    def test_monitor_domains__skips_a_fresh_check(self, org, domain_queue):
        make_monitored(org)

        monitor_domains.func()

        assert domain_queue.calls == []

    def test_monitor_domains__skips_a_suspended_org(self, org, domain_queue):
        backdate(make_monitored(org), hours=2)
        org.suspended_at = timezone.now()
        org.save(update_fields=["suspended_at"])

        monitor_domains.func()

        assert domain_queue.calls == []
        assert (
            DomainCheck.objects.get(name="example.com").status
            == DomainCheck.Status.COMPLETE
        )

    def test_monitor_domains__skips_an_unmonitored_check(self, domain_queue):
        backdate(make_check(), hours=2)

        monitor_domains.func()

        assert domain_queue.calls == []

    def test_monitor_domains__skips_a_managed_domain(self, org, domain_queue):
        managed = Domain.objects.get(org=org, is_managed=True)
        DomainCheck.objects.create(
            name=managed.name,
            domain=managed,
            status=DomainCheck.Status.PENDING,
        )

        monitor_domains.func()

        assert domain_queue.calls == []


@pytest.mark.django_db
class TestEnqueueCheck:
    def test_enqueue_check__stamps_a_pending_row_and_queues(self, domain_queue):
        check = make_check(status=DomainCheck.Status.COMPLETE)
        backdate = timezone.now() - dt.timedelta(days=1)
        DomainCheck.objects.filter(pk=check.pk).update(modified_at=backdate)

        enqueue_check("example.com")

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.PENDING
        assert check.modified_at > backdate
        assert domain_queue.calls == [{"name": "example.com"}]

    def test_enqueue_check__restart_clears_a_finished_check(self, domain_queue):
        check = make_check(status=DomainCheck.Status.COMPLETE, checks=[{"key": "mx"}])

        enqueue_check("example.com", restart=True)

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.PENDING
        assert check.checks == []
        assert domain_queue.calls == [{"name": "example.com"}]

    def test_enqueue_check__restart_leaves_a_running_check_alone(self, domain_queue):
        check = make_check(status=DomainCheck.Status.RUNNING, checks=[{"key": "mx"}])

        enqueue_check("example.com", restart=True)

        check.refresh_from_db()
        assert check.status == DomainCheck.Status.RUNNING
        assert check.checks == [{"key": "mx"}]
        assert domain_queue.calls == []

    def test_enqueue_check__an_unknown_name_queues_nothing(self, domain_queue):
        enqueue_check("unknown.example")

        assert domain_queue.calls == []


@pytest.mark.django_db
class TestEnqueueChanges:
    def test_enqueue_changes__queues_the_mail_for_the_linked_domain(
        self, org, mail_queue
    ):
        domain = Domain.objects.create(name="example.com", org=org)
        changes = [{"check_key": "spf"}]

        enqueue_changes("example.com", changes)

        assert mail_queue.calls == [
            {"domain_name": "example.com", "domain_pk": domain.pk, "changes": changes}
        ]

    def test_enqueue_changes__drops_a_name_without_a_domain(self, mail_queue, caplog):
        with caplog.at_level(logging.INFO, logger="domains.check.tasks"):
            enqueue_changes("example.com", [])

        assert mail_queue.calls == []
        assert "the domain is missing" in caplog.text


class FlakyMailer:
    def __init__(self, *, fail_first=False):
        self.fail_first = fail_first
        self.messages = []
        self.attempts = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def send_messages(self, messages):
        self.attempts += 1
        if self.fail_first and self.attempts == 1:
            raise OSError
        self.messages.extend(messages)


CHANGES = [
    {
        "check_key": "spf",
        "check_label": "SPF",
        "subcheck_label": "Strict all",
        "detail": "Ends with ~all.",
        "hint": "End the SPF record with -all instead of ~all.",
        "previous_status": "pass",
        "current_status": "fail",
    }
]


def make_monitor_domain(org, name="example.com", **fields):
    make_monitored(org, name=name, **fields)
    return Domain.objects.get(name=name)


@pytest.mark.django_db
class TestSendDomainCheckChanges:
    def test_send_domain_check_changes__mails_each_member_once(
        self, org, user, mailoutbox
    ):
        domain = make_monitor_domain(org)

        send_domain_check_changes.func(
            domain_name="example.com", domain_pk=domain.pk, changes=CHANGES
        )

        assert [message.to[0] for message in mailoutbox] == ["alice@example.com"]
        assert "Strict all needs attention" in mailoutbox[0].subject

    def test_send_domain_check_changes__skips_a_suspended_org(
        self, org, mailoutbox, caplog
    ):
        domain = make_monitor_domain(org)
        org.suspended_at = timezone.now()
        org.save(update_fields=["suspended_at"])

        with caplog.at_level(logging.INFO, logger="domains.check.tasks"):
            send_domain_check_changes.func(
                domain_name="example.com", domain_pk=domain.pk, changes=CHANGES
            )

        assert mailoutbox == []
        assert "missing or suspended" in caplog.text

    def test_send_domain_check_changes__skips_a_mismatched_name(self, org, mailoutbox):
        domain = make_monitor_domain(org)

        send_domain_check_changes.func(
            domain_name="other.example", domain_pk=domain.pk, changes=CHANGES
        )

        assert mailoutbox == []

    def test_send_domain_check_changes__keeps_mailing_after_a_failure(
        self, org, other_user, mailoutbox, monkeypatch, caplog
    ):
        Membership.objects.create(org=org, user=other_user)
        domain = make_monitor_domain(org)
        mailer = FlakyMailer(fail_first=True)
        monkeypatch.setattr(
            "domains.check.tasks.mailers", SimpleNamespace(default=mailer)
        )

        with caplog.at_level(logging.WARNING, logger="domains.check.tasks"):
            send_domain_check_changes.func(
                domain_name="example.com", domain_pk=domain.pk, changes=CHANGES
            )

        assert mailer.attempts == 2
        assert [message.to[0] for message in mailer.messages] == ["bob@example.com"]
        assert "Domain monitor mail for user" in caplog.text


@pytest.mark.django_db
class TestCheckWorkersNotify:
    def fill_every_check(self):
        DomainCheck.objects.filter(name="example.com").update(
            status=DomainCheck.Status.RUNNING, checks=[]
        )
        for worker in (check_delivery, check_authentication, check_reputation):
            worker.func(name="example.com")

    @staticmethod
    def passing_baseline(checks):
        baseline = copy.deepcopy(checks)
        for row in baseline:
            for subcheck in row.get("subchecks", []):
                subcheck["status"] = "pass"
        return baseline

    @pytest.mark.parametrize(
        "worker",
        [check_delivery, check_authentication, check_reputation],
        ids=["delivery", "authentication", "reputation"],
    )
    def test_worker__queues_the_changes_when_a_record_flips(
        self, org, dns_resolver, monkeypatch, worker
    ):
        make_monitor_domain(org)
        self.fill_every_check()
        check = DomainCheck.objects.get(name="example.com")
        DomainCheck.objects.filter(pk=check.pk).update(
            status=DomainCheck.Status.RUNNING,
            previous_checks=self.passing_baseline(check.checks),
        )
        calls = []

        def record(domain_name, changes):
            calls.append({"domain_name": domain_name, "changes": changes})

        monkeypatch.setattr("domains.check.tasks.enqueue_changes", record)

        worker.func(name="example.com")

        assert [call["domain_name"] for call in calls] == ["example.com"]
        assert calls[0]["changes"]
