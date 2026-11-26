import django.db.models.deletion
from django.db import migrations, models


def link_domain_checks(apps, schema_editor):
    Domain = apps.get_model("domains", "Domain")
    DomainCheck = apps.get_model("domains", "DomainCheck")
    for domain in Domain.objects.filter(is_managed=False).iterator():
        try:
            domain_check = DomainCheck.objects.get(name=domain.name)
        except DomainCheck.DoesNotExist:
            DomainCheck.objects.create(name=domain.name, domain=domain)
        else:
            if domain_check.status == "complete" and not domain_check.previous_checks:
                domain_check.previous_checks = domain_check.checks
            domain_check.domain = domain
            domain_check.save(update_fields=["domain", "previous_checks"])


class Migration(migrations.Migration):
    dependencies = [
        ("domains", "0005_remove_domaincheck_checked_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="domaincheck",
            name="domain",
            field=models.OneToOneField(
                blank=True,
                help_text="Domain this check monitors.",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="domain_check",
                to="domains.domain",
            ),
        ),
        migrations.AddField(
            model_name="domaincheck",
            name="previous_checks",
            field=models.JSONField(
                default=list,
                help_text="The last completed result, compared against each new run.",
                verbose_name="previous checks",
            ),
        ),
        migrations.RunPython(link_domain_checks, migrations.RunPython.noop),
    ]
