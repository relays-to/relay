import base64
import dataclasses
import datetime as dt
import hashlib
from collections.abc import Iterable, Mapping
from functools import reduce
from operator import or_

import idna
import validators
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models.functions import Length, Lower
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from abstract.models import TimeStamped
from kms.models import SigningKey

from .check.evaluation import Check, CheckResult
from .check.jurisdictions import get_country_name
from .check.tiers import Tier


def canonicalize_domain_name(value):
    """Return the lowercase ASCII UTS-46 form of a domain name."""
    try:
        return idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError) as error:
        raise ValidationError(
            _("Enter a valid domain name, for example acme.com")
        ) from error


def validate_domain_name(value):
    """Validate that *value* is a syntactically valid domain name."""
    if validators.domain(canonicalize_domain_name(value)) is not True:
        raise ValidationError(_("Enter a valid domain name, for example acme.com"))


def validate_mta_sts_mx_hosts(value):
    """Validate a list of MTA-STS MX hosts with optional RFC 8461 wildcards."""
    if not isinstance(value, list):
        raise ValidationError(_("MX hosts must be a list."))
    for hostname in value:
        if not isinstance(hostname, str):
            raise ValidationError(_("Each MX host must be a string."))
        validate_domain_name(hostname.removeprefix("*."))


class DomainQuerySet(models.QuerySet):
    def root_for(self, name, *, include_managed):
        """
        Return the closest registered parent domain for *name*.

        If more than one ancestor domain exists, the most specific
        name has priority.

        Raises:
            DoesNotExist: If no matching domain is found.

        """
        try:
            parts = idna.uts46_remap(
                name,
                std3_rules=False,
                transitional=False,
            ).split(".")
        except (idna.IDNAError, UnicodeError) as error:
            raise self.model.DoesNotExist from error
        candidates = []
        for index in range(len(parts)):
            try:
                candidate = canonicalize_domain_name(".".join(parts[index:]))
            except ValidationError:
                candidate = None
            if candidate is not None:
                candidates.append(candidate)
        if not candidates:
            raise self.model.DoesNotExist
        qs = self.filter(
            reduce(or_, (models.Q(name__iexact=c) for c in candidates)),
        )
        if not include_managed:
            qs = qs.filter(is_managed=False)
        domains = list(qs.select_related("org").order_by(Length("name").desc()))
        # The platform domain is the ancestor of every managed sender
        # domain by design, so it may share an ancestor chain with
        # domains of other organizations without making the match ambiguous.
        if len({domain.org_id for domain in domains}) > 1:
            platform_name = canonicalize_domain_name(settings.PLATFORM_DOMAIN)
            domains = [domain for domain in domains if domain.name != platform_name]
        if not domains or len({domain.org_id for domain in domains}) > 1:
            raise self.model.DoesNotExist
        return domains[0]


class Domain(TimeStamped):
    DELEGATION_CHECK_FIELDS = ("nameserver",)
    SENDING_CHECK_FIELDS = ("spf", "dkim_rsa2048", "dkim_ed25519")
    SENDING_READINESS_FIELDS = (*DELEGATION_CHECK_FIELDS, *SENDING_CHECK_FIELDS)
    SENDING_QUICK_START_FIELDS = (*DELEGATION_CHECK_FIELDS, "spf", "dkim_rsa2048")
    RECEIVING_CHECK_FIELDS = ("mx",)
    REPORTING_CHECK_FIELDS = ("dmarc", "mta_sts", "tls_rpt")
    REPORTING_READINESS_FIELDS = (*DELEGATION_CHECK_FIELDS, *REPORTING_CHECK_FIELDS)

    class VerificationMethod(models.TextChoices):
        DNS = "dns", _("DNS")
        EMAIL = "email", _("email")

    class Status(models.TextChoices):
        OK = "ok", _("ok")
        ERROR = "error", _("error")
        PENDING = "pending", _("pending")
        UNCHECKED = "unchecked", _("unchecked")

    name = models.CharField(
        _("name"),
        max_length=255,
        unique=True,
        validators=[validate_domain_name],
        help_text=_("Root domain, for example acme.com."),
    )
    org = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="domains",
        help_text=_("Owning organization."),
    )
    verified_at = models.DateTimeField(
        _("verified at"),
        null=True,
        blank=True,
        help_text=_("When DNS verification completed."),
    )
    nameserver_status = models.TextField(
        _("nameserver status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("NS delegation check result for the sender subdomain."),
    )
    nameserver_error = models.TextField(
        _("nameserver error"),
        blank=True,
        help_text=_("Failure detail if NS delegation is incorrect."),
    )
    spf_status = models.TextField(
        _("SPF status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("SPF record check result on the root domain."),
    )
    spf_error = models.TextField(
        _("SPF error"),
        blank=True,
        help_text=_("Failure detail if the SPF record is incorrect."),
    )
    dkim_rsa2048_status = models.TextField(
        _("RSA-2048 DKIM status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("RSA-2048 DKIM CNAME check result on the root domain."),
    )
    dkim_rsa2048_error = models.TextField(
        _("RSA-2048 DKIM error"),
        blank=True,
        help_text=_("Failure detail if the RSA-2048 DKIM CNAME is incorrect."),
    )
    dkim_ed25519_status = models.TextField(
        _("Ed25519 DKIM status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("Ed25519 DKIM CNAME check result on the root domain."),
    )
    dkim_ed25519_error = models.TextField(
        _("Ed25519 DKIM error"),
        blank=True,
        help_text=_("Failure detail if the Ed25519 DKIM CNAME is incorrect."),
    )
    dmarc_status = models.TextField(
        _("DMARC status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("DMARC record check result on the root domain."),
    )
    dmarc_error = models.TextField(
        _("DMARC error"),
        blank=True,
        help_text=_("Failure detail if the DMARC record is incorrect."),
    )
    mx_status = models.TextField(
        _("MX status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("MX record check result on the root domain."),
    )
    mx_error = models.TextField(
        _("MX error"),
        blank=True,
        help_text=_("Failure detail if the MX record is incorrect."),
    )
    mta_sts_status = models.TextField(
        _("MTA-STS status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("MTA-STS record check result on the root domain."),
    )
    mta_sts_error = models.TextField(
        _("MTA-STS error"),
        blank=True,
        help_text=_("Failure detail if the MTA-STS record is incorrect."),
    )
    mta_sts_mx_hostnames = models.JSONField(
        _("MTA-STS MX hosts"),
        default=list,
        blank=True,
        validators=[validate_mta_sts_mx_hosts],
        help_text=_(
            "MX hosts for the MTA-STS policy. Empty follows the MX record hostnames."
        ),
    )
    tls_rpt_status = models.TextField(
        _("TLS-RPT status"),
        choices=Status,
        default=Status.UNCHECKED,
        help_text=_("TLS-RPT record check result on the root domain."),
    )
    tls_rpt_error = models.TextField(
        _("TLS-RPT error"),
        blank=True,
        help_text=_("Failure detail if the TLS-RPT record is incorrect."),
    )
    dns_checked_at = models.DateTimeField(
        _("DNS checked at"),
        null=True,
        blank=True,
        help_text=_("Last DNS check timestamp."),
    )

    dkim_key_rsa2048 = models.ForeignKey(
        "kms.SigningKey",
        on_delete=models.PROTECT,
        related_name="+",
        null=True,
        blank=True,
        help_text=_("RSA-2048 DKIM signing key."),
    )
    dkim_key_ed25519 = models.ForeignKey(
        "kms.SigningKey",
        on_delete=models.PROTECT,
        related_name="+",
        null=True,
        blank=True,
        help_text=_("Ed25519 DKIM signing key."),
    )

    def __str__(self):
        return f"{self.name} (managed)" if self.is_managed else self.name

    def __repr__(self):
        return f"<Domain {self.pk}>"

    class Meta(TimeStamped.Meta):
        indexes = [
            models.Index(Lower("name"), name="domain_name_lower_idx"),
        ]

    objects = models.Manager.from_queryset(DomainQuerySet)()

    def get_absolute_url(self):
        return reverse(
            "domains:domain-detail",
            kwargs={"org_slug": self.org.slug, "pk": self.pk},
        )

    def save(self, *args, **kwargs):
        self.name = canonicalize_domain_name(self.name)
        self.clean()
        is_new = self.pk is None
        super().save(*args, **kwargs)
        if is_new and self.dkim_key_rsa2048_id is None:
            self.dkim_key_rsa2048 = SigningKey.generate(SigningKey.Algorithm.RSA_2048)
            self.dkim_key_ed25519 = SigningKey.generate(SigningKey.Algorithm.ED25519)
            super().save(
                update_fields=[
                    "dkim_key_rsa2048",
                    "dkim_key_ed25519",
                ]
            )

    @property
    def is_verified(self):
        return self.verified_at is not None

    def checks_passing(self, fields) -> int:
        return sum(
            getattr(self, f"{field}_status") == self.Status.OK for field in fields
        )

    @property
    def delegation_checks_passing(self):
        return self.checks_passing(self.DELEGATION_CHECK_FIELDS)

    @property
    def sending_checks_passing(self):
        return self.checks_passing(self.SENDING_READINESS_FIELDS)

    @property
    def receiving_checks_passing(self):
        return self.checks_passing(self.RECEIVING_CHECK_FIELDS)

    @property
    def reporting_checks_passing(self):
        return self.checks_passing(self.REPORTING_READINESS_FIELDS)

    @property
    def is_sending_verified(self):
        """Return whether the domain passes the sending quick start."""
        return self.checks_passing(self.SENDING_QUICK_START_FIELDS) == len(
            self.SENDING_QUICK_START_FIELDS
        )

    is_managed = models.BooleanField(
        _("managed"),
        default=False,
        help_text=_("Whether relay manages this domain's DNS automatically."),
    )

    def clean(self):
        name = canonicalize_domain_name(self.name)
        self.name = name
        platform_name = canonicalize_domain_name(settings.PLATFORM_DOMAIN)
        if not self.is_managed:
            root = canonicalize_domain_name(settings.MANAGED_SENDER_DOMAIN)
            if name == root or name.endswith(f".{root}"):
                raise ValidationError(
                    _(
                        "Cannot add a subdomain of %(base)s. relay manages these automatically."
                    )
                    % {"base": root}
                )
            # A name below the platform domain answers for relay's own MX,
            # SMTP, and policy hosts, so only relay-managed rows may use one.
            if name.endswith(f".{platform_name}"):
                raise ValidationError(
                    _(
                        "Cannot add a subdomain of %(base)s. relay manages these automatically."
                    )
                    % {"base": platform_name}
                )

        if self.org_id:
            parts = name.split(".")
            ancestors = [".".join(parts[index:]) for index in range(len(parts))]
            overlapping_domains = Domain.objects.exclude(org_id=self.org_id).filter(
                reduce(or_, (models.Q(name__iexact=value) for value in ancestors))
                | models.Q(name__iendswith=f".{name}")
            )
            # The platform domain is the ancestor of every managed sender
            # domain by design, so a conflict is skipped exactly when one
            # of the two rows' canonical name is the platform domain.
            if name == platform_name:
                overlapping_domains = Domain.objects.none()
            else:
                overlapping_domains = overlapping_domains.exclude(
                    name__iexact=platform_name
                )
            if self.pk:
                overlapping_domains = overlapping_domains.exclude(pk=self.pk)
            if overlapping_domains.exists():
                raise ValidationError(
                    {
                        "name": _(
                            "Domain overlaps with a domain owned by another organization."
                        )
                    }
                )

    @property
    def dkim_ciphers(self):
        prefix = settings.DNS_DKIM_IDENTIFIER
        return [
            ("dkim_rsa2048", f"{prefix}-rsa2048", self.dkim_key_rsa2048),
            ("dkim_ed25519", f"{prefix}-ed25519", self.dkim_key_ed25519),
        ]

    @property
    def sender_domain(self):
        """Return the subdomain used as the SMTP envelope and DKIM sender."""
        return f"{settings.SENDER_SUBDOMAIN_PREFIX}.{self.name}"

    @property
    def dmarc_record_name(self):
        return f"_dmarc.{self.name}"

    def dkim_cname_for_selector(self, selector: str) -> tuple[str, str]:
        base = self.sender_domain
        name = f"{selector}._domainkey.{self.name}"
        target = f"{selector}._domainkey.{base}"
        return name, target

    @property
    def dkim_cnames(self):
        return {
            field: self.dkim_cname_for_selector(selector)
            for field, selector, _key in self.dkim_ciphers
        }

    @property
    def spf_record(self):
        """Return the SPF record with one ip4 term per relay sending address."""
        terms = [f"ip4:{address}" for address in settings.DNS_SMTP_IPS]
        return " ".join(["v=spf1", *terms, "-all"])

    @property
    def root_spf_record(self):
        return f"v=spf1 include:{self.sender_domain} -all"

    @property
    def dmarc_reporting_address(self):
        return f"{settings.DMARC_REPORT_LOCAL_PART}@{self.sender_domain}"

    @property
    def dmarc_ruf_reporting_address(self):
        return f"{settings.DMARC_RUF_LOCAL_PART}@{self.sender_domain}"

    @property
    def tls_reporting_address(self):
        return f"{settings.TLS_REPORT_LOCAL_PART}@{self.sender_domain}"

    @property
    def dmarc_record(self):
        """Return the DMARC record for the root domain, with rua/ruf pointing to the sender subdomain."""
        return (
            f"v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r;"
            f" rua=mailto:{self.dmarc_reporting_address};"
            f" ruf=mailto:{self.dmarc_ruf_reporting_address};"
        )

    @property
    def tls_rpt_record_name(self):
        """Return the TLS-RPT record name at the root domain."""
        return f"_smtp._tls.{self.name}"

    @property
    def tls_rpt_record(self):
        """Return the TLS-RPT TXT value with rua pointing to the sender subdomain."""
        return f"v=TLSRPTv1;rua=mailto:{self.tls_reporting_address}"

    @property
    def tls_rpt_record_cname_target(self):
        """Return the target of the TLS-RPT CNAME inside the sender subdomain."""
        return f"_smtp._tls.{self.sender_domain}"

    @property
    def sender_dmarc_record(self):
        """Return the DMARC record served at _dmarc.{sender_subdomain} for external reporting authorization."""
        return "v=DMARC1; p=quarantine"

    @property
    def mta_sts_mx_hosts(self):
        """Return the MX hosts the MTA-STS policy advertises."""
        return self.mta_sts_mx_hostnames or settings.DNS_MX_HOSTNAMES

    @property
    def mta_sts_policy_id(self):
        """Return the policy id derived from the policy content."""
        digest = hashlib.sha256(
            "\n".join(
                [
                    settings.MTA_STS_MODE,
                    str(settings.MTA_STS_MAX_AGE),
                    *self.mta_sts_mx_hosts,
                ]
            ).encode()
        ).digest()
        return base64.b32encode(digest[:16], padded=False).decode()

    @property
    def mta_sts_record_name(self):
        return f"_mta-sts.{self.name}"

    @property
    def mta_sts_record(self):
        """Return the MTA-STS DNS record for _mta-sts.{domain}."""
        return f"v=STSv1; id={self.mta_sts_policy_id}"

    @property
    def mta_sts_record_cname_target(self):
        """Return the target of the MTA-STS CNAME inside the sender subdomain."""
        return f"_mta-sts.{self.sender_domain}"

    @property
    def mta_sts_hostname(self):
        """Return the host senders fetch the policy from."""
        return f"mta-sts.{self.name}"

    @property
    def mta_sts_cname_target(self):
        """Return the policy host inside the sender subdomain."""
        return f"mta-sts.{self.sender_domain}"


class DomainCheck(TimeStamped):
    CHECK_INTERVAL = dt.timedelta(days=1)
    MONITOR_INTERVAL = dt.timedelta(hours=1)

    class Status(models.TextChoices):
        PENDING = "pending", _("pending")
        RUNNING = "running", _("running")
        COMPLETE = "complete", _("complete")
        FAILED = "failed", _("failed")

    name = models.CharField(
        _("domain"),
        max_length=255,
        unique=True,
        validators=[validate_domain_name],
        help_text=_("Domain name without a scheme."),
    )
    status = models.TextField(
        _("status"),
        choices=Status,
        default=Status.PENDING,
    )
    penalty = models.PositiveSmallIntegerField(
        _("penalty"),
        default=0,
        db_index=True,
        help_text=_("Half tiers lost. A blocking failure pins the tier to F."),
    )
    checks = models.JSONField(
        _("checks"),
        default=list,
        help_text=_("One result per authentication check."),
    )
    domain = models.OneToOneField(
        "Domain",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="domain_check",
        help_text=_("Domain this check monitors."),
    )
    previous_checks = models.JSONField(
        _("previous checks"),
        default=list,
        help_text=_("The last completed result, compared against each new run."),
    )

    class Meta(TimeStamped.Meta):
        ordering = ["penalty", "-modified_at"]

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<DomainCheck {self.pk}>"

    def get_absolute_url(self):
        return reverse("domain_check:detail", kwargs={"name": self.name})

    @property
    def is_stale(self) -> bool:
        if self.status == self.Status.PENDING:
            return True
        if self.domain_id is not None:
            return timezone.now() - self.modified_at > self.MONITOR_INTERVAL
        if self.status == self.Status.FAILED:
            return True
        return timezone.now() - self.modified_at > self.CHECK_INTERVAL

    @classmethod
    def for_domain(cls, domain: Domain) -> DomainCheck:
        domain_check, _created = cls.objects.get_or_create(
            name=domain.name, defaults={"domain": domain}
        )
        if domain_check.domain_id is not None:
            return domain_check
        fields = {"domain": domain}
        if (
            domain_check.status == cls.Status.COMPLETE
            and not domain_check.previous_checks
        ):
            fields["previous_checks"] = domain_check.checks
        cls.objects.filter(pk=domain_check.pk).update(**fields)
        domain_check.domain = domain
        return domain_check

    @staticmethod
    def flatten_checks(
        checks: Iterable[Mapping],
    ) -> dict[tuple[str, int], tuple[str, str, str]]:
        return {
            (check["key"], index): (
                check["label"],
                subcheck["label"],
                subcheck["status"],
            )
            for check in checks
            for index, subcheck in enumerate(check.get("subchecks", []))
        }

    def calculate_changes(self, previous_checks: Iterable[Mapping]) -> list[dict]:
        previous = self.flatten_checks(previous_checks)
        changes = []
        for (check_key, subcheck_index), (
            check_label,
            subcheck_label,
            current_status,
        ) in self.flatten_checks(self.checks).items():
            _, _, previous_status = previous.get(
                (check_key, subcheck_index), (None, None, None)
            )
            if (previous_status, current_status) in {
                ("pass", "fail"),
                ("fail", "pass"),
                (None, "fail"),
            }:
                changes.append(
                    {
                        "check_key": check_key,
                        "check_label": check_label,
                        "subcheck_label": subcheck_label,
                        "previous_status": previous_status,
                        "current_status": current_status,
                    }
                )
        return changes

    @staticmethod
    def build_check_row(check: dict) -> dict:
        subchecks = [
            {
                "severity": "broken",
                "hint": Check.hint_for(check["key"], subcheck["label"]),
            }
            | subcheck
            for subcheck in check.get("subchecks", [])
        ]
        return check | {
            "slug": Check.slugs().get(check["key"]),
            "subchecks": subchecks,
            "issue_count": sum(
                subcheck["status"] not in {"pass", "skip"} for subcheck in subchecks
            ),
        }

    @property
    def check_rows(self) -> list[dict]:
        return [
            self.build_check_row(check)
            for check in self.checks
            if check["key"] in Check.order()
        ]

    @property
    def issue_count(self) -> int:
        return sum(row["issue_count"] for row in self.check_rows)

    @property
    def jurisdiction_flags(self) -> tuple[dict[str, str | tuple[str, ...]], ...]:
        jurisdictions = [
            check.get("metadata", {}).get("jurisdiction")
            for check in self.checks
            if check.get("key") in {"mx", "spf"}
        ]
        jurisdictions = [
            jurisdiction
            for jurisdiction in jurisdictions
            if jurisdiction and jurisdiction.get("country_codes")
        ]
        if not jurisdictions:
            return ()
        sources: dict[str, list[str]] = {}
        country_codes: list[str] = []
        for jurisdiction in jurisdictions:
            for provider in jurisdiction.get("providers", []):
                country_code = provider.get("country_code")
                if country_code and provider.get("provider_name"):
                    sources.setdefault(country_code, []).append(
                        provider["provider_name"]
                    )
            for network in jurisdiction.get("networks", []):
                country_code = network.get("country_code")
                if country_code and network.get("asn"):
                    network_name = network.get("network_name")
                    label = (
                        f"{network_name} (AS{network['asn']})"
                        if network_name
                        else f"AS{network['asn']}"
                    )
                    sources.setdefault(country_code, []).append(label)
            for country_code in jurisdiction.get("country_codes", []):
                if country_code not in country_codes:
                    country_codes.append(country_code)
        return tuple(
            {
                "country_code": country_code,
                "country_name": str(get_country_name(country_code)),
                "sources": tuple(dict.fromkeys(sources[country_code])),
                "flag_url": f"https://flagcdn.com/{country_code.lower()}.svg",
            }
            for country_code in country_codes
            if country_code in sources and len(country_code) == 2
        )

    @staticmethod
    def serialize_result(result: CheckResult) -> dict:
        data = dataclasses.asdict(result)
        if not data.get("metadata"):
            data.pop("metadata", None)
        return data | {"status": result.status}

    @classmethod
    def store(cls, name: str, results: Iterable[CheckResult]) -> list[dict] | None:
        with transaction.atomic():
            domain_check = cls.objects.select_for_update().get(name=name)
            if domain_check.status != cls.Status.RUNNING:
                return None
            merged = {check["key"]: check for check in domain_check.checks}
            merged.update(
                {result.key: cls.serialize_result(result) for result in results}
            )
            checks = [merged[key] for key in Check.order() if key in merged]
            domain_check.checks = checks
            update_fields = ["checks"]
            changes = None
            if len(checks) == len(Check.order()):
                domain_check.penalty = cls.penalty_for(checks)
                domain_check.status = cls.Status.COMPLETE
                update_fields += ["penalty", "status"]
                if domain_check.domain_id is not None:
                    changes = (
                        domain_check.calculate_changes(domain_check.previous_checks)
                        if domain_check.previous_checks
                        else []
                    )
                    domain_check.previous_checks = checks
                    update_fields.append("previous_checks")
                else:
                    changes = []
            domain_check.save(update_fields=update_fields)
            return changes

    @classmethod
    def penalty_for(cls, checks: Iterable[Mapping]) -> int:
        failed = [
            subcheck
            for check in checks
            for subcheck in check.get("subchecks", [])
            if subcheck["status"] == "fail"
        ]
        if any(subcheck.get("severity", "broken") == "blocking" for subcheck in failed):
            return len(Tier) - 1
        return sum(
            2 if subcheck.get("severity", "broken") == "broken" else 1
            for subcheck in failed
        )

    @property
    def issue_phrase(self) -> str:
        """Return how many checks need attention, in words."""
        if self.issue_count == 0:
            return "All checks pass"
        suffix = "s" if self.issue_count != 1 else ""
        verb = "needs" if self.issue_count == 1 else "need"
        return f"{self.issue_count} issue{suffix} {verb} attention"

    @property
    def status_line(self) -> str:
        """Return the one line status a card prints under the domain."""
        match self.status:
            case self.Status.COMPLETE:
                return self.issue_phrase
            case self.Status.FAILED:
                return "The last check failed"
            case _:
                return "Check in progress"

    @property
    def tier_letter(self) -> str:
        """Return the tier, or a dash while the check has not finished."""
        return str(self.tier) if self.status == self.Status.COMPLETE else "\u2013"

    @property
    def tier(self) -> Tier:
        return list(Tier)[min(self.penalty, len(Tier) - 1)]

    @property
    def tier_variant(self) -> str:
        return self.tier.variant
