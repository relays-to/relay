from django.db import migrations


def mark_soft_bounced_messages(apps, schema_editor):
    """Move messages and attempts a 4xx refusal ended to the new status."""
    outgoing_message = apps.get_model("msa", "OutgoingMessage")
    transmission = apps.get_model("message", "Transmission")
    refusals = transmission.objects.filter(
        status="failed",
        code__gte=400,
        code__lt=500,
    )
    outgoing_message.objects.filter(
        status="failed",
        pk__in=refusals.values("message_id"),
    ).update(status="soft_bounced")
    refusals.update(status="soft_bounced")


class Migration(migrations.Migration):
    dependencies = [
        ("msa", "0007_alter_suppressionentry_address_hash"),
        ("message", "0003_alter_transmission_status"),
    ]

    operations = [
        migrations.RunPython(mark_soft_bounced_messages, migrations.RunPython.noop),
    ]
