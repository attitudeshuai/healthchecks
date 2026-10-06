from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from hc.api.models import Channel, CredentialAccess
from hc.lib import crypto
from hc.lib.credentials import get_keyring, reset_keyring
from hc.test import BaseTestCase


def b64key(seed: bytes) -> str:
    return base64.urlsafe_b64encode(seed).decode()


NEW_KEY = b64key(b"1" * 32)
OLD_KEY = b64key(b"2" * 32)
MYSTERY_KEY = b64key(b"3" * 32)
OLD_KEYS_JSON = json.dumps([{"id": "old", "alg": "A256GCM", "key": OLD_KEY}])

DOC = json.dumps({"url": "https://example.org", "token": "abc"})


def stored(channel: Channel) -> str:
    """Read the raw stored value, bypassing decryption."""

    return Channel.objects.filter(id=channel.id).values_list("value", flat=True)[0]


@contextmanager
def use_encryption() -> Iterator[None]:
    with override_settings(
        CREDENTIALS_ENCRYPTION=True,
        CREDENTIALS_ALGORITHM="A256GCM",
        CREDENTIALS_KEY_ID="new",
        CREDENTIALS_KEY=NEW_KEY,
        CREDENTIALS_OLD_KEYS=OLD_KEYS_JSON,
        CREDENTIALS_AUDIT_RETENTION_DAYS=365,
    ):
        reset_keyring()
        try:
            yield
        finally:
            reset_keyring()


class ReencryptTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        reset_keyring()
        self.addCleanup(reset_keyring)

        self.old = crypto.make_key("old", crypto.A256GCM, OLD_KEY)
        self.new = crypto.make_key("new", crypto.A256GCM, NEW_KEY)
        self.mystery = crypto.make_key("mystery", crypto.A256GCM, MYSTERY_KEY)

    def make_channel(self, raw: str) -> Channel:
        # Encryption is off during setUp, so create() stores the raw value.
        return Channel.objects.create(project=self.project, kind="gotify", value=raw)

    def test_it_migrates_plain_and_old_records(self) -> None:
        plain = self.make_channel(DOC)
        outdated = self.make_channel(crypto.encrypt(DOC, self.old))
        current = self.make_channel(crypto.encrypt(DOC, self.new))
        undecryptable = self.make_channel(crypto.encrypt(DOC, self.mystery))

        current_envelope = stored(current)
        mystery_envelope = stored(undecryptable)

        with use_encryption():
            stdout, stderr = StringIO(), StringIO()
            call_command("reencrypt", stdout=stdout, stderr=stderr)
            output = stdout.getvalue()

            self.assertIn("Migrated: 2", output)
            self.assertIn("failed: 1", output)
            self.assertIn("mystery", stderr.getvalue())

            # Plaintext record is now encrypted with the current key
            self.assertTrue(stored(plain).startswith("enc$1$A256GCM$new$"))
            self.assertEqual(Channel.objects.get(id=plain.id).gotify.token, "abc")

            # Old-key record is now encrypted with the current key
            self.assertTrue(stored(outdated).startswith("enc$1$A256GCM$new$"))
            self.assertEqual(Channel.objects.get(id=outdated.id).gotify.token, "abc")

            # Current-key record was skipped byte-for-byte
            self.assertEqual(stored(current), current_envelope)

            # Undecryptable record is preserved untouched
            self.assertEqual(stored(undecryptable), mystery_envelope)

            # Rotation audit rows for the two migrated records only
            audits = CredentialAccess.objects.filter(action=CredentialAccess.ROTATE)
            self.assertEqual(audits.count(), 2)
            self.assertEqual(set(audits.values_list("key_id", flat=True)), {"new"})

    def test_it_is_idempotent_on_rerun(self) -> None:
        self.make_channel(crypto.encrypt(DOC, self.old))

        with use_encryption():
            call_command("reencrypt", stdout=StringIO())
            stdout = StringIO()
            call_command("reencrypt", stdout=stdout)

            self.assertIn("Migrated: 0", stdout.getvalue())
            self.assertEqual(
                CredentialAccess.objects.filter(
                    action=CredentialAccess.ROTATE
                ).count(),
                1,
            )

    def test_it_respects_batch_size_and_start(self) -> None:
        c1 = self.make_channel(crypto.encrypt(DOC, self.old))
        c2 = self.make_channel(crypto.encrypt(DOC, self.old))
        c3 = self.make_channel(crypto.encrypt(DOC, self.old))

        with use_encryption():
            stdout = StringIO()
            call_command("reencrypt", batch_size=1, stdout=stdout)
            self.assertIn("Migrated: 3", stdout.getvalue())

            # Reset all three back to the old key
            for c in (c1, c2, c3):
                Channel.objects.filter(id=c.id).update(value=crypto.encrypt(DOC, self.old))

            # Start after c1's id: c1 must be left untouched
            stdout = StringIO()
            call_command("reencrypt", start=c1.id, stdout=stdout)

            self.assertTrue(stored(c1).startswith("enc$1$A256GCM$old$"))
            self.assertTrue(stored(c2).startswith("enc$1$A256GCM$new$"))
            self.assertTrue(stored(c3).startswith("enc$1$A256GCM$new$"))

    def test_it_does_not_overwrite_concurrent_writes(self) -> None:
        from hc.api.management.commands.reencrypt import reencrypt_one

        channel = self.make_channel(crypto.encrypt(DOC, self.old))

        with use_encryption():
            keyring = get_keyring()
            original_encrypt = keyring.encrypt

            def writer_then_encrypt(plaintext: str) -> str:
                # Simulate a concurrent sender that re-saves the same row
                # with a current-key envelope while we are re-encrypting.
                concurrent_doc = json.dumps(
                    {"url": "https://example.org", "token": "concurrent-write"}
                )
                concurrent_envelope = original_encrypt(concurrent_doc)
                Channel.objects.filter(id=channel.id).update(
                    value=concurrent_envelope
                )
                return original_encrypt(plaintext)

            keyring.encrypt = writer_then_encrypt  # type: ignore[method-assign]
            try:
                status, _message = reencrypt_one(
                    channel.id, keyring, keyring.current_envelope_prefix()
                )
            finally:
                keyring.encrypt = original_encrypt  # type: ignore[method-assign]

            self.assertEqual(status, "skipped")
            # The concurrent writer's value is intact and decrypts correctly
            self.assertTrue(stored(channel).startswith("enc$1$A256GCM$new$"))
            refreshed = Channel.objects.get(id=channel.id)
            self.assertEqual(refreshed.gotify.token, "concurrent-write")
            self.assertFalse(
                CredentialAccess.objects.filter(
                    action=CredentialAccess.ROTATE
                ).exists()
            )

    def test_it_refuses_to_run_when_disabled(self) -> None:
        with override_settings(CREDENTIALS_ENCRYPTION=False):
            reset_keyring()
            with self.assertRaises(CommandError):
                call_command("reencrypt")


class PruneCredentialAccessCommandTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        reset_keyring()
        self.addCleanup(reset_keyring)

    def test_it_prunes_old_records(self) -> None:
        channel = Channel.objects.create(project=self.project, kind="gotify")
        CredentialAccess.objects.create(
            channel=channel, action=CredentialAccess.READ, key_id="new"
        )
        with override_settings(CREDENTIALS_AUDIT_RETENTION_DAYS=365):
            stdout = StringIO()
            call_command("prunecredentialaccess", stdout=stdout)
            # A fresh record is kept
            self.assertEqual(CredentialAccess.objects.count(), 1)
