from __future__ import annotations

from datetime import timedelta as td
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.timezone import now

from hc.accounts.models import ApiKeyAudit, ApiKeyCredential, governance_seconds


class Command(BaseCommand):
    help = """Govern API keys when rotation/expiry is enabled.

    It performs three housekeeping tasks:
        - marks previous keys invalid once their rotation window has ended,
        - marks current keys invalid past their expiry + grace period,
        - deletes API key audit records past the audit retention period.

    Schedule it to run every API_KEY_PRUNE_SCAN_PERIOD seconds.
    """

    def handle(self, **options: Any) -> str:
        ts = now()

        windowed = ApiKeyCredential.objects.filter(
            status=ApiKeyCredential.Status.PREVIOUS,
            window_expires_at__isnull=False,
            window_expires_at__lte=ts,
        ).update(
            status=ApiKeyCredential.Status.INVALID,
            invalid_reason=ApiKeyCredential.InvalidReason.WINDOW,
        )

        expired = 0
        if settings.API_KEY_EXPIRATION_ENABLED:
            grace_cutoff = ts - td(
                seconds=governance_seconds("API_KEY_EXPIRATION_GRACE")
            )
            expired = ApiKeyCredential.objects.filter(
                status=ApiKeyCredential.Status.CURRENT,
                expires_at__isnull=False,
                expires_at__lte=grace_cutoff,
            ).update(
                status=ApiKeyCredential.Status.INVALID,
                invalid_reason=ApiKeyCredential.InvalidReason.EXPIRED,
            )

        # Retention is a startup-validated setting when governance is enabled;
        # skip the step if it is unset/non-positive (e.g. command run while
        # governance is disabled with a customized duration value).
        retention = settings.API_KEY_AUDIT_RETENTION
        if retention and retention > 0:
            n_audits, _ = ApiKeyAudit.objects.filter(
                created_at__lt=ts - td(seconds=retention)
            ).delete()
        else:
            n_audits = 0

        self.stdout.write(
            f"Invalidated {windowed} previous key(s) past their rotation window."
        )
        self.stdout.write(
            f"Invalidated {expired} current key(s) past their expiry grace."
        )
        self.stdout.write(f"Pruned {n_audits} API key audit record(s).")

        return "Done!"
