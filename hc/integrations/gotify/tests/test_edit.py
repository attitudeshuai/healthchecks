from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager

from django.test import override_settings

from hc.api.models import Channel, Check, CredentialAccess
from hc.lib.credentials import reset_keyring
from hc.test import BaseTestCase


@contextmanager
def use_encryption() -> Iterator[None]:
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    with override_settings(
        CREDENTIALS_ENCRYPTION=True,
        CREDENTIALS_ALGORITHM="A256GCM",
        CREDENTIALS_KEY_ID="current",
        CREDENTIALS_KEY=key,
        CREDENTIALS_OLD_KEYS=None,
        CREDENTIALS_AUDIT_RETENTION_DAYS=365,
    ):
        reset_keyring()
        try:
            yield
        finally:
            reset_keyring()


class EditGotifyTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.check = Check.objects.create(project=self.project)

        self.channel = Channel(project=self.project, kind="gotify")
        self.channel.value = json.dumps(
            {
                "url": "https://example.org",
                "token": "test-token",
                "priority": 5,
                "priority_up": 5,
            }
        )
        self.channel.save()

        self.url = f"/integrations/{self.channel.code}/edit/"

    def test_instructions_work(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.get(self.url)
        self.assertContains(r, "Save Integration")
        self.assertContains(r, "https://example.org")
        self.assertContains(r, "test-token")

    def test_it_updates_channel(self) -> None:
        form = {
            "url": "https://example.com",
            "token": "updated-token",
            "priority": "9",
            "priority_up": "2",
        }

        self.client.login(username="alice@example.org", password="password")
        r = self.client.post(self.url, form)
        self.assertRedirects(r, self.channels_url)

        self.channel.refresh_from_db()
        self.assertEqual(self.channel.gotify.url, "https://example.com")
        self.assertEqual(self.channel.gotify.token, "updated-token")
        self.assertEqual(self.channel.gotify.priority, 9)
        self.assertEqual(self.channel.gotify.priority_up, 2)

        # Make sure it does not call assign_all_checks
        self.assertFalse(self.channel.checks.exists())

    def test_it_requires_rw_access(self) -> None:
        self.bobs_membership.role = "r"
        self.bobs_membership.save()

        self.client.login(username="bob@example.org", password="password")
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 403)


class EncryptedEditGotifyTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.check = Check.objects.create(project=self.project)
        self._encryption = use_encryption()
        self._encryption.__enter__()
        self.addCleanup(self._encryption.__exit__, None, None, None)

        self.channel = Channel(project=self.project, kind="gotify")
        self.channel.value = json.dumps(
            {
                "url": "https://example.org",
                "token": "test-token",
                "priority": 5,
                "priority_up": 5,
            }
        )
        self.channel.save()
        self.url = f"/integrations/{self.channel.code}/edit/"

        self.client.login(username="alice@example.org", password="password")

    def test_it_does_not_refill_token(self) -> None:
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "test-token")
        self.assertContains(r, "already set")
        # Non-sensitive fields are still shown
        self.assertContains(r, "https://example.org")

        # The credential read is audited, key id only, no credential content
        access = CredentialAccess.objects.get()
        self.assertEqual(access.action, "read")
        self.assertEqual(access.key_id, "current")

    def test_blank_token_keeps_existing_value(self) -> None:
        form = {"url": "https://example.com", "priority": "9", "priority_up": "2"}
        r = self.client.post(self.url, form)
        self.assertRedirects(r, self.channels_url)

        self.channel.refresh_from_db()
        self.assertEqual(self.channel.gotify.token, "test-token")
        self.assertEqual(self.channel.gotify.url, "https://example.com")

        # The stored row contains no plaintext token
        raw = Channel.objects.filter(id=self.channel.id).values_list(
            "value", flat=True
        )[0]
        self.assertTrue(raw.startswith("enc$1$A256GCM$current$"))
        self.assertNotIn("test-token", raw)

    def test_new_token_replaces_existing(self) -> None:
        form = {
            "url": "https://example.org",
            "token": "fresh-token",
            "priority": "5",
            "priority_up": "5",
        }
        r = self.client.post(self.url, form)
        self.assertRedirects(r, self.channels_url)

        self.channel.refresh_from_db()
        self.assertEqual(self.channel.gotify.token, "fresh-token")
