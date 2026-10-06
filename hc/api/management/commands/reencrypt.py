"""Re-encrypt channel credentials with the current encryption key.

Migrates both plaintext (never-encrypted) historical records and records
encrypted with old keys to the current key. Safe to interrupt and re-run:
records already encrypted with the current key are skipped, and a guarded
UPDATE makes sure records re-written by concurrent senders are not clobbered.
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from hc.api.models import Channel, CredentialAccess
from hc.lib import crypto
from hc.lib.credentials import Keyring, get_keyring

MIGRATED = "migrated"
SKIPPED = "skipped"
FAILED = "failed"


def reencrypt_one(channel_id: int, keyring: Keyring, current_prefix: str) -> tuple[str, str]:
    """Re-encrypt a single channel row.

    Returns a (status, message) tuple where status is one of MIGRATED,
    SKIPPED or FAILED.
    """

    with transaction.atomic():
        rows = list(
            Channel.objects.select_for_update()
            .filter(id=channel_id)
            .values_list("value", "code")
        )
        if not rows:
            return SKIPPED, "channel no longer exists"

        raw_value, code = rows[0]
        if not raw_value or raw_value.startswith(current_prefix):
            # Empty value, or already encrypted with the current key.
            return SKIPPED, "already current"

        try:
            if crypto.is_envelope(raw_value):
                plaintext, _used_key = keyring.decrypt_record(raw_value)
            else:
                plaintext = raw_value
            new_value = keyring.encrypt(plaintext)
        except crypto.CredentialError as e:
            # Roll back and leave the original record untouched.
            return FAILED, f"{code}: {e}"

        # Guard against overwriting a row that a concurrent writer updated
        # after we read it (e.g. a new notification write during rotation).
        updated = Channel.objects.filter(id=channel_id, value=raw_value).update(
            value=new_value
        )
        if updated == 0:
            return SKIPPED, "updated concurrently"

        assert keyring.current is not None
        CredentialAccess.objects.create(
            channel_id=channel_id,
            action=CredentialAccess.ROTATE,
            key_id=keyring.current.id,
        )

    return MIGRATED, str(code)


class Command(BaseCommand):
    help = "Re-encrypt channel credentials using the current key"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--batch-size",
            type=int,
            default=200,
            help="Number of channels to process per database batch.",
        )
        parser.add_argument(
            "--start",
            type=int,
            default=0,
            help="Channel id to start from (exclusive). Useful for resuming.",
        )

    def handle(self, batch_size: int, start: int, **options: Any) -> str:
        keyring = get_keyring()
        if not keyring.enabled or keyring.current is None:
            raise CommandError(
                "Channel credential encryption is not enabled. Set "
                "CREDENTIALS_ENCRYPTION=True and configure CREDENTIALS_KEY_ID "
                "and CREDENTIALS_KEY first."
            )

        current_prefix = keyring.current_envelope_prefix()

        migrated = skipped = failed = 0
        last_id = start

        while True:
            batch = list(
                Channel.objects.filter(id__gt=last_id)
                .exclude(value="")
                .exclude(value__startswith=current_prefix)
                .order_by("id")
                .values_list("id", flat=True)[:batch_size]
            )
            if not batch:
                break

            for channel_id in batch:
                result, message = reencrypt_one(channel_id, keyring, current_prefix)
                if result == MIGRATED:
                    migrated += 1
                elif result == SKIPPED:
                    skipped += 1
                else:
                    failed += 1
                    # Keep the record untouched and continue with other channels.
                    self.stderr.write(f"Failed to re-encrypt channel {message}")

            last_id = batch[-1]
            self.stdout.write(f"Processed up to id {last_id}")

        summary = (
            f"Done. Migrated: {migrated}, skipped: {skipped}, failed: {failed}."
        )
        self.stdout.write(summary)
        return summary
