from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from hc.api.models import CredentialAccess


class Command(BaseCommand):
    help = "Prune channel credential access audit records older than the retention period"

    def handle(self, **options: Any) -> str:
        retention = settings.CREDENTIALS_AUDIT_RETENTION_DAYS or 365
        deleted = CredentialAccess.objects.prune(retention)
        msg = f"Deleted {deleted} credential access record(s)."
        self.stdout.write(msg)
        return msg
