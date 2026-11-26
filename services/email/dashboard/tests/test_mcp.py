import datetime as dt
import json

import pytest
from django.utils import timezone

from domains.models import Domain
from services.email.message.mcp import MessageNotFoundError, get_message_transmissions
from services.email.message.models import Transmission
from services.email.msa.models import OutgoingMessage


def create_outgoing_message(org):
    return OutgoingMessage.objects.create(
        org=org,
        domain=Domain.objects.get(org=org, is_managed=True),
        mail_from="alice@example.com",
        rcpt_to="bob@example.net",
    )


@pytest.mark.django_db
class TestGetMessageTransmissions:
    def test_get_message_transmissions__returns_each_leg_oldest_first(self, org, user):
        message = create_outgoing_message(org)
        started_at = timezone.now()
        Transmission.objects.create(
            message=message,
            status=Transmission.Status.RETRY,
            code=451,
            output="451 4.7.1 Try again",
            remote_host="mx.remote.example",
            started_at=started_at,
            finished_at=started_at,
        )
        Transmission.objects.create(
            message=message,
            status=Transmission.Status.SENT,
            code=250,
            output="250 2.0.0 Ok",
            remote_host="mx.remote.example",
            tls_mode=Transmission.TlsMode.TLS,
            tls_version="TLSv1.3",
            started_at=started_at + dt.timedelta(seconds=5),
            finished_at=started_at + dt.timedelta(seconds=6),
        )

        payload = json.loads(get_message_transmissions(message.id, user=user))

        assert payload["message_id"] == str(message.id)
        assert [
            (transmission["status"], transmission["code"])
            for transmission in payload["transmissions"]
        ] == [("retry", 451), ("sent", 250)]
        assert payload["transmissions"][1]["duration_secs"] == 1

    def test_get_message_transmissions__not_found_for_other_org_message(
        self, org, other_user
    ):
        message = create_outgoing_message(org)

        with pytest.raises(MessageNotFoundError):
            get_message_transmissions(message.id, user=other_user)
