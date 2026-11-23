import datetime as dt

from django.db import migrations
from django.utils import timezone

from accounts.models import Organization
from services.email.dashboard import tasks
from services.email.dashboard.onboarding import (
    SEND_OFFSETS,
    OnboardingStage,
    get_onboarding_state,
)

# The welcome mail went out at sign-up. These are the mails that follow it.
REMINDER_OFFSETS = {
    stage: offset
    for stage, offset in SEND_OFFSETS.items()
    if stage != OnboardingStage.WELCOME
}


def remaining_send_times(
    start: dt.datetime, now: dt.datetime
) -> dict[OnboardingStage, dt.datetime]:
    """
    Return when to send the reminders after the welcome mail.

    Keep the sign-up time of day. Send the first reminder within a day of
    `now` and space the rest like the original offsets, so sign-ups from
    different time zones land at different times.
    """
    local_start = timezone.localtime(start)
    local_now = timezone.localtime(now)
    first = local_now.replace(
        hour=local_start.hour,
        minute=local_start.minute,
        second=local_start.second,
        microsecond=local_start.microsecond,
    )
    if first <= local_now:
        first += dt.timedelta(days=1)
    shift = first - (local_start + SEND_OFFSETS[OnboardingStage.FIRST_REMINDER])
    return {
        stage: local_start + offset + shift
        for stage, offset in REMINDER_OFFSETS.items()
    }


def schedule_reminders(apps, schema_editor):
    """
    Queue the reminders that threadmill dropped before 0.10.1.

    The welcome mail went out. Keep the sign-up time of day and send the first
    reminder within a day, so the sequence does not land all at once.
    """
    now = timezone.now()
    for organization in Organization.objects.filter(suspended_at__isnull=True):
        if not get_onboarding_state(organization)["onboarding_complete"]:
            for stage, run_after in remaining_send_times(
                organization.created_at, now
            ).items():
                tasks.send_onboarding_email.using(run_after=run_after).enqueue(
                    org_pk=organization.pk,
                    stage=stage,
                )


class Migration(migrations.Migration):
    dependencies = [
        ("dashboard", "0001_backfill_onboarding"),
        ("domains", "0005_remove_domaincheck_checked_at"),
        ("msa", "0007_alter_suppressionentry_address_hash"),
    ]

    operations = [
        migrations.RunPython(schedule_reminders, migrations.RunPython.noop),
    ]
