import pytest

from accounts.models import Organization
from domains.models import Domain, DomainCheck
from domains.signals import monitor_domain


@pytest.mark.django_db
class TestSynchronizeManagedDomain:
    def test_create__creates_verified_managed_domain(self, settings):
        org = Organization.objects.create(slug="acme")

        domain = Domain.objects.get(org=org, is_managed=True)
        assert domain.name == f"acme.{settings.MANAGED_SENDER_DOMAIN}"
        assert domain.verified_at is not None
        assert domain.dns_checked_at is not None
        assert {
            domain.nameserver_status,
            domain.spf_status,
            domain.dkim_rsa2048_status,
            domain.dkim_ed25519_status,
            domain.dmarc_status,
            domain.mta_sts_status,
            domain.tls_rpt_status,
        } == {Domain.Status.OK}

    def test_slug_change__renames_existing_managed_domain(self, settings):
        org = Organization.objects.create(slug="acme")
        domain = Domain.objects.get(org=org, is_managed=True)
        domain_id = domain.pk
        key_ids = (
            domain.dkim_key_rsa2048_id,
            domain.dkim_key_ed25519_id,
        )

        org.slug = "renamed"
        org.save(update_fields=["slug"])

        domain.refresh_from_db()
        assert domain.pk == domain_id
        assert domain.name == f"renamed.{settings.MANAGED_SENDER_DOMAIN}"
        assert (
            domain.dkim_key_rsa2048_id,
            domain.dkim_key_ed25519_id,
        ) == key_ids
        assert Domain.objects.filter(org=org, is_managed=True).count() == 1


@pytest.mark.django_db
class TestMonitorDomain:
    def test_create__links_a_check_and_queues_the_first_run(
        self, org, monkeypatch, django_capture_on_commit_callbacks
    ):
        queued = []
        monkeypatch.setattr("domains.signals.enqueue_check", queued.append)

        with django_capture_on_commit_callbacks(execute=True):
            domain = Domain.objects.create(name="example.com", org=org)

        domain_check = DomainCheck.objects.get(domain=domain)
        assert domain_check.name == "example.com"
        assert domain_check.status == DomainCheck.Status.PENDING
        assert queued == ["example.com"]

    def test_create__keeps_a_fresh_free_check(
        self, org, monkeypatch, django_capture_on_commit_callbacks
    ):
        DomainCheck.objects.create(
            name="example.com",
            status=DomainCheck.Status.COMPLETE,
            checks=[{"key": "mx", "label": "MX", "detail": "", "subchecks": []}],
        )
        queued = []
        monkeypatch.setattr("domains.signals.enqueue_check", queued.append)

        with django_capture_on_commit_callbacks(execute=True):
            domain = Domain.objects.create(name="example.com", org=org)

        domain_check = DomainCheck.objects.get(domain=domain)
        assert domain_check.previous_checks == []
        assert queued == []

    def test_create__does_not_monitor_a_managed_domain(
        self, org, monkeypatch, django_capture_on_commit_callbacks
    ):
        queued = []
        monkeypatch.setattr("domains.signals.enqueue_check", queued.append)

        with django_capture_on_commit_callbacks(execute=True):
            Domain.objects.get(org=org, is_managed=True).save()

        assert not DomainCheck.objects.filter(domain__is_managed=True).exists()
        assert queued == []

    def test_save__does_not_queue_again(
        self, org, monkeypatch, django_capture_on_commit_callbacks
    ):
        domain = Domain.objects.create(name="example.com", org=org)
        DomainCheck.objects.filter(name="example.com").update(
            status=DomainCheck.Status.COMPLETE
        )
        queued = []
        monkeypatch.setattr("domains.signals.enqueue_check", queued.append)

        with django_capture_on_commit_callbacks(execute=True):
            domain.save(update_fields=["name"])

        assert queued == []

    def test_save__skips_a_raw_save(self):
        monitor_domain(
            sender=Domain,
            instance=Domain(name="example.com"),
            created=True,
            raw=True,
        )

        assert not DomainCheck.objects.exists()
