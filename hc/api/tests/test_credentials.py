from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta as td
from unittest.mock import Mock, patch

from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from django.utils.timezone import now

from hc.api.apps import settings_check
from hc.api.models import Channel, Check, CredentialAccess, Flip
from hc.lib import crypto
from hc.lib.credentials import get_keyring, reset_keyring
from hc.test import BaseTestCase


def b64key(seed: bytes) -> str:
    return base64.urlsafe_b64encode(seed).decode()


NEW_KEY = b64key(b"1" * 32)
OLD_KEY = b64key(b"2" * 32)
MYSTERY_KEY = b64key(b"3" * 32)

OLD_KEYS_JSON = json.dumps([{"id": "old", "alg": "A256GCM", "key": OLD_KEY}])


@contextmanager
def use_encryption(**kwargs: object) -> Iterator[None]:
    opts = {
        "CREDENTIALS_ENCRYPTION": True,
        "CREDENTIALS_ALGORITHM": "A256GCM",
        "CREDENTIALS_KEY_ID": "new",
        "CREDENTIALS_KEY": NEW_KEY,
        "CREDENTIALS_OLD_KEYS": OLD_KEYS_JSON,
        "CREDENTIALS_AUDIT_RETENTION_DAYS": 365,
    }
    opts.update(kwargs)
    with override_settings(**opts):
        reset_keyring()
        try:
            yield
        finally:
            reset_keyring()


def raw_value(channel: Channel) -> str:
    """Read the raw stored value, bypassing decryption."""

    return Channel.objects.filter(id=channel.id).values_list("value", flat=True)[0]


class CredentialEncryptionTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        reset_keyring()
        self.addCleanup(reset_keyring)

        self.check = Check.objects.create(project=self.project)
        self.definition = json.dumps(
            {"url": "https://example.org", "token": "abc", "priority": 5}
        )

    def make_gotify(self, value: str) -> Channel:
        channel = Channel(project=self.project, kind="gotify")
        channel.value = value
        channel.save()
        channel.checks.add(self.check)
        return channel

    def test_it_is_disabled_by_default(self) -> None:
        channel = self.make_gotify(self.definition)
        self.assertEqual(raw_value(channel), self.definition)
        self.assertEqual(channel.gotify.token, "abc")
        self.assertEqual(channel.credential_key_id(), "")

    def test_it_encrypts_at_rest_when_enabled(self) -> None:
        with use_encryption():
            channel = self.make_gotify(self.definition)

            raw = raw_value(channel)
            self.assertTrue(raw.startswith("enc$1$A256GCM$new$"))
            self.assertNotIn("abc", raw)
            self.assertNotIn("example.org", raw)

            # In-process reads still see plaintext
            self.assertEqual(channel.gotify.url, "https://example.org")
            self.assertEqual(channel.gotify.token, "abc")
            self.assertEqual(channel.credential_key_id(), "new")

    def test_it_decrypts_freshly_loaded_instance(self) -> None:
        with use_encryption():
            channel_id = self.make_gotify(self.definition).id

            channel = Channel.objects.get(id=channel_id)
            self.assertEqual(channel.gotify.token, "abc")

    def test_it_reads_records_encrypted_with_old_key(self) -> None:
        with use_encryption():
            channel = self.make_gotify(self.definition)

        # Simulate a record from a previous key rotation
        old = crypto.make_key("old", crypto.A256GCM, OLD_KEY)
        old_envelope = crypto.encrypt(self.definition, old)
        Channel.objects.filter(id=channel.id).update(value=old_envelope)

        with use_encryption():
            channel = Channel.objects.get(id=channel.id)
            self.assertEqual(channel.gotify.token, "abc")
            self.assertEqual(channel.credential_key_id(), "old")

    def test_it_raises_when_no_matching_key(self) -> None:
        with use_encryption():
            channel = self.make_gotify(self.definition)

        mystery = crypto.make_key("mystery", crypto.A256GCM, MYSTERY_KEY)
        bad_envelope = crypto.encrypt(self.definition, mystery)
        Channel.objects.filter(id=channel.id).update(value=bad_envelope)

        with use_encryption():
            channel = Channel.objects.get(id=channel.id)
            with self.assertRaises(crypto.CredentialError):
                channel.gotify.token

            # The stored record is preserved untouched
            self.assertEqual(raw_value(channel), bad_envelope)
            self.assertFalse(Channel.objects.get(id=channel.id).disabled)

    def test_it_does_not_encrypt_blank_values(self) -> None:
        with use_encryption():
            channel = self.make_gotify("")
            self.assertEqual(raw_value(channel), "")

    @patch("hc.api.transports.curl.request", autospec=True)
    def test_notify_works_with_encrypted_credentials(self, mock_post: Mock) -> None:
        mock_post.return_value.status_code = 200
        with use_encryption():
            channel = self.make_gotify(self.definition)

            flip = Flip(owner=self.check, old_status="up", new_status="down")
            flip.created = now()
            self.assertEqual(channel.notify(flip), "")

            _, url = mock_post.call_args.args
            self.assertEqual(url, "https://example.org/message?token=abc")

            access = CredentialAccess.objects.get()
            self.assertEqual(access.action, CredentialAccess.READ)
            self.assertEqual(access.key_id, "new")
            self.assertFalse(Channel.objects.get(id=channel.id).disabled)

    @patch("hc.api.transports.curl.request", autospec=True)
    def test_notify_works_with_old_key_and_audits_decrypt(
        self, mock_post: Mock
    ) -> None:
        mock_post.return_value.status_code = 200
        with use_encryption():
            channel = self.make_gotify(self.definition)

        old = crypto.make_key("old", crypto.A256GCM, OLD_KEY)
        Channel.objects.filter(id=channel.id).update(
            value=crypto.encrypt(self.definition, old)
        )

        with use_encryption():
            channel = Channel.objects.get(id=channel.id)
            flip = Flip(owner=self.check, old_status="up", new_status="down")
            flip.created = now()
            self.assertEqual(channel.notify(flip), "")

            access = CredentialAccess.objects.get()
            self.assertEqual(access.action, CredentialAccess.DECRYPT)
            self.assertEqual(access.key_id, "old")

    @patch("hc.api.transports.curl.request", autospec=True)
    def test_notify_reports_error_and_keeps_channel_on_decrypt_failure(
        self, mock_post: Mock
    ) -> None:
        with use_encryption():
            channel = self.make_gotify(self.definition)

        mystery = crypto.make_key("mystery", crypto.A256GCM, MYSTERY_KEY)
        bad_envelope = crypto.encrypt(self.definition, mystery)
        Channel.objects.filter(id=channel.id).update(value=bad_envelope)

        with use_encryption():
            channel = Channel.objects.get(id=channel.id)
            flip = Flip(owner=self.check, old_status="up", new_status="down")
            flip.created = now()
            error = channel.notify(flip)

            self.assertIn("mystery", error)
            mock_post.assert_not_called()
            self.assertFalse(Channel.objects.get(id=channel.id).disabled)
            # No audit row for a failed read
            self.assertEqual(CredentialAccess.objects.count(), 0)

    @patch("hc.api.transports.curl.request", autospec=True)
    def test_undecryptable_channel_does_not_block_others(
        self, mock_post: Mock
    ) -> None:
        mock_post.return_value.status_code = 200
        with use_encryption():
            good = self.make_gotify(self.definition)
            bad = self.make_gotify(
                json.dumps({"url": "https://evil.example", "token": "xyz"})
            )

        mystery = crypto.make_key("mystery", crypto.A256GCM, MYSTERY_KEY)
        bad_env = crypto.encrypt(
            json.dumps({"url": "https://evil.example", "token": "xyz"}), mystery
        )
        Channel.objects.filter(id=bad.id).update(value=bad_env)

        with use_encryption():
            flip = Flip(owner=self.check, old_status="up", new_status="down")
            flip.created = now()

            channels = flip.select_channels()
            self.assertEqual(set(channels), {Channel.objects.get(id=good.id), Channel.objects.get(id=bad.id)})

            self.assertEqual(good.notify(flip), "")
            self.assertIn("mystery", Channel.objects.get(id=bad.id).notify(flip))

            # The good channel's notification was still sent
            mock_post.assert_called_once()

    def test_audit_query_by_channel_and_time(self) -> None:
        with use_encryption():
            channel = self.make_gotify(self.definition)
            other = self.make_gotify(self.definition)
            channel.audit_credential_access()
            old_access = CredentialAccess.objects.get(channel=channel)
            CredentialAccess.objects.filter(id=old_access.id).update(
                created=now() - td(days=10)
            )
            channel.audit_credential_access()
            other.audit_credential_access()

            recent = CredentialAccess.objects.for_channel(
                channel, since=now() - td(days=1)
            )
            self.assertEqual(recent.count(), 1)

            self.assertEqual(CredentialAccess.objects.for_channel(other).count(), 1)

    def test_audit_records_store_no_credentials(self) -> None:
        field_names = {f.name for f in CredentialAccess._meta.get_fields()}
        self.assertEqual(
            field_names, {"id", "channel", "action", "key_id", "created"}
        )

    def test_prune_deletes_old_audit_records(self) -> None:
        with use_encryption():
            channel = self.make_gotify(self.definition)
            channel.audit_credential_access()
            CredentialAccess.objects.update(created=now() - td(days=400))

            deleted = CredentialAccess.objects.prune(365)
            self.assertEqual(deleted, 1)
            self.assertEqual(CredentialAccess.objects.count(), 0)


class KeyringValidationTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        reset_keyring()
        self.addCleanup(reset_keyring)

    def test_it_requires_current_key_id(self) -> None:
        with use_encryption(CREDENTIALS_KEY_ID=None):
            with self.assertRaises(ImproperlyConfigured):
                get_keyring()

    def test_it_requires_current_key_material(self) -> None:
        with use_encryption(CREDENTIALS_KEY=None):
            with self.assertRaises(ImproperlyConfigured):
                get_keyring()

    def test_it_rejects_short_key(self) -> None:
        with use_encryption(CREDENTIALS_KEY=b64key(b"too-short")):
            with self.assertRaises(ImproperlyConfigured):
                get_keyring()

    def test_it_rejects_bad_old_keys_json(self) -> None:
        with use_encryption(CREDENTIALS_OLD_KEYS="not json"):
            with self.assertRaises(ImproperlyConfigured):
                get_keyring()

    def test_it_rejects_duplicate_key_ids(self) -> None:
        olds = json.dumps([{"id": "new", "key": OLD_KEY}])
        with use_encryption(CREDENTIALS_OLD_KEYS=olds):
            with self.assertRaises(ImproperlyConfigured):
                get_keyring()

    def test_it_rejects_bad_retention(self) -> None:
        with use_encryption(CREDENTIALS_AUDIT_RETENTION_DAYS=0):
            with self.assertRaises(ImproperlyConfigured):
                get_keyring()

    def test_it_loads_when_disabled_without_keys(self) -> None:
        with override_settings(CREDENTIALS_ENCRYPTION=False):
            self.assertFalse(get_keyring().enabled)


class CredentialSystemCheckTestCase(BaseTestCase):
    def test_it_reports_error_when_enabled_without_key(self) -> None:
        with use_encryption(CREDENTIALS_KEY=None):
            ids = [item.id for item in settings_check(None, None)]
            self.assertIn("hc.api.E004", ids)

    def test_it_reports_error_for_short_key(self) -> None:
        with use_encryption(CREDENTIALS_KEY=b64key(b"short")):
            ids = [item.id for item in settings_check(None, None)]
            self.assertIn("hc.api.E004", ids)

    def test_it_passes_with_valid_configuration(self) -> None:
        with use_encryption():
            ids = [item.id for item in settings_check(None, None)]
            self.assertNotIn("hc.api.E004", ids)

    def test_it_silent_when_disabled(self) -> None:
        with override_settings(CREDENTIALS_ENCRYPTION=False):
            ids = [item.id for item in settings_check(None, None)]
            self.assertNotIn("hc.api.E004", ids)
