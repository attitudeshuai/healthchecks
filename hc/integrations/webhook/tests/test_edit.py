from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager

from django.test import override_settings

from hc.api.models import Channel, Check
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


class EditWebhookTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.check = Check.objects.create(project=self.project)

        definition = {
            "method_down": "GET",
            "url_down": "http://example.org/down",
            "body_down": "$NAME is down",
            "headers_down": {"User-Agent": "My-Custom-UA"},
            "method_up": "GET",
            "url_up": "http://example.org/up",
            "body_up": "$NAME is up",
            "headers_up": {},
        }

        self.channel = Channel(project=self.project, kind="webhook")
        self.channel.name = "Call example.org"
        self.channel.value = json.dumps(definition)
        self.channel.save()

        self.url = f"/integrations/{self.channel.code}/edit/"

    def test_it_shows_form(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.get(self.url)
        self.assertContains(r, "Webhook Settings")

        self.assertContains(r, "Call example.org")

        # down
        self.assertContains(r, "http://example.org/down")
        self.assertContains(r, "My-Custom-UA")
        self.assertContains(r, "$NAME is down")

        # up
        self.assertContains(r, "http://example.org/up")
        self.assertContains(r, "$NAME is up")

    def test_it_saves_form_and_redirects(self) -> None:
        form = {
            "name": "Call foo.com / bar.com",
            "method_down": "POST",
            "url_down": "http://foo.com",
            "headers_down": "X-Foo: 1\nX-Bar: 2",
            "body_down": "going down",
            "method_up": "POST",
            "url_up": "https://bar.com",
            "headers_up": "Content-Type: text/plain",
            "body_up": "going up",
        }

        self.client.login(username="alice@example.org", password="password")
        r = self.client.post(self.url, form)
        self.assertRedirects(r, self.channels_url)

        self.channel.refresh_from_db()
        self.assertEqual(self.channel.name, "Call foo.com / bar.com")

        down_spec = self.channel.down_webhook_spec
        self.assertEqual(down_spec.method, "POST")
        self.assertEqual(down_spec.url, "http://foo.com")
        self.assertEqual(down_spec.body, "going down")
        self.assertEqual(down_spec.headers, {"X-Foo": "1", "X-Bar": "2"})

        up_spec = self.channel.up_webhook_spec
        self.assertEqual(up_spec.method, "POST")
        self.assertEqual(up_spec.url, "https://bar.com")
        self.assertEqual(up_spec.body, "going up")
        self.assertEqual(up_spec.headers, {"Content-Type": "text/plain"})

        # Make sure it does not call assign_all_checks
        self.assertFalse(self.channel.checks.exists())

    def test_it_requires_kind_webhook(self) -> None:
        self.channel.kind = "shell"
        self.channel.save()

        self.client.login(username="alice@example.org", password="password")
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 400)

    def test_it_requires_rw_access(self) -> None:
        self.bobs_membership.role = "r"
        self.bobs_membership.save()

        self.client.login(username="bob@example.org", password="password")
        r = self.client.post(self.url, {})
        self.assertEqual(r.status_code, 403)


class EncryptedEditWebhookTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.check = Check.objects.create(project=self.project)

        definition = {
            "method_down": "GET",
            "url_down": "http://example.org/down",
            "body_down": "$NAME is down",
            "headers_down": {"User-Agent": "My-Custom-UA"},
            "method_up": "GET",
            "url_up": "http://example.org/up",
            "body_up": "$NAME is up",
            "headers_up": {},
        }

        self._encryption = use_encryption()
        self._encryption.__enter__()
        self.addCleanup(self._encryption.__exit__, None, None, None)

        self.channel = Channel(project=self.project, kind="webhook")
        self.channel.name = "Call example.org"
        self.channel.value = json.dumps(definition)
        self.channel.save()

        self.url = f"/integrations/{self.channel.code}/edit/"
        self.client.login(username="alice@example.org", password="password")

    def test_it_does_not_refill_urls_and_headers(self) -> None:
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "http://example.org/down")
        self.assertNotContains(r, "http://example.org/up")
        self.assertNotContains(r, "My-Custom-UA")
        # Non-sensitive values are still pre-filled
        self.assertContains(r, "$NAME is down")
        # Hints are shown for the configured fields
        self.assertContains(r, "A URL is already set", count=2)
        self.assertContains(r, "Custom headers are already set")

    def test_blank_sensitive_fields_keep_existing_values(self) -> None:
        form = {
            "name": "Call example.org",
            "method_down": "GET",
            "body_down": "$NAME is down",
            "method_up": "GET",
            "body_up": "$NAME is up",
        }
        r = self.client.post(self.url, form)
        self.assertRedirects(r, self.channels_url)

        self.channel.refresh_from_db()
        down = self.channel.down_webhook_spec
        self.assertEqual(down.url, "http://example.org/down")
        self.assertEqual(down.headers, {"User-Agent": "My-Custom-UA"})
        up = self.channel.up_webhook_spec
        self.assertEqual(up.url, "http://example.org/up")

        raw = Channel.objects.filter(id=self.channel.id).values_list(
            "value", flat=True
        )[0]
        self.assertTrue(raw.startswith("enc$1$A256GCM$current$"))
        self.assertNotIn("example.org", raw)

    def test_new_values_replace_existing(self) -> None:
        form = {
            "name": "Call foo.com",
            "method_down": "POST",
            "url_down": "http://foo.com/down",
            "headers_down": "X-Foo: 1",
            "body_down": "going down",
            "method_up": "GET",
            "url_up": "",
            "body_up": "",
        }
        r = self.client.post(self.url, form)
        self.assertRedirects(r, self.channels_url)

        self.channel.refresh_from_db()
        down = self.channel.down_webhook_spec
        self.assertEqual(down.url, "http://foo.com/down")
        self.assertEqual(down.headers, {"X-Foo": "1"})
        # Blank up URL keeps the previously configured up URL
        self.assertEqual(self.channel.up_webhook_spec.url, "http://example.org/up")
