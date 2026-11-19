from urllib.parse import unquote_plus

import pytest
from allauth.idp.oidc.models import Client
from django.urls import reverse

from abstract.open_graph import signer


@pytest.mark.django_db
class TestAuthorizationView:
    def make_client(self, name="Claude"):
        return Client.objects.create(
            name=name,
            redirect_uris="https://example.com/callback",
        )

    def test_get__uses_a_signed_client_name_share_card(self, admin_client):
        client = self.make_client()

        response = admin_client.get(
            reverse("idp:oidc:authorization"),
            {
                "response_type": "code",
                "client_id": client.pk,
                "redirect_uri": "https://example.com/callback",
                "scope": "openid",
                "state": "state-1",
            },
        )

        assert response.status_code == 200
        content = response.content.decode()
        signature = content.split("/og.png?signature=")[1].split('"')[0]
        assert signer.unsign(unquote_plus(signature)) == "Authorize Claude"
