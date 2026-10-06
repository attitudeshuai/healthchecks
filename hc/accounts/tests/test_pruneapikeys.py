from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.core.management import call_command
from django.test.utils import override_settings

from hc.accounts.models import ApiKeyAudit, ApiKeyCredential, Project
from hc.test import BaseTestCase

RW = ApiKeyCredential.Slot.RW
C = ApiKeyCredential.Status.CURRENT
P = ApiKeyCredential.Status.PREVIOUS
I = ApiKeyCredential.Status.INVALID
WINDOW = ApiKeyCredential.InvalidReason.WINDOW
EXPIRED = ApiKeyCredential.InvalidReason.EXPIRED

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def cred(project: Project, **kw: Any) -> ApiKeyCredential:
    args: dict[str, Any] = dict(slot=RW, key_hash="X" * 32, prefix="", status=C)
    args.update(kw)
    return ApiKeyCredential.objects.create(project=project, **args)


def audit(
    project: Project | None = None, created_at: datetime | None = None
) -> ApiKeyAudit:
    return ApiKeyAudit.objects.create(
        project=project,
        slot=RW,
        key_prefix="abcd1234",
        result=ApiKeyAudit.Result.ACCEPTED,
        source=ApiKeyAudit.Source.HEADER,
        created_at=created_at or NOW,
    )


@override_settings(
    API_KEY_ROTATION_ENABLED=True,
    API_KEY_EXPIRATION_ENABLED=True,
    API_KEY_EXPIRATION_GRACE=100,
    API_KEY_AUDIT_RETENTION=1000,
)
class PruneApiKeysTestCase(BaseTestCase):
    def run_command(self) -> str:
        out = StringIO()
        with patch("hc.accounts.management.commands.pruneapikeys.now", return_value=NOW):
            call_command("pruneapikeys", stdout=out)
        return out.getvalue()

    def test_it_invalidates_window_ended_previous_keys(self) -> None:
        keep = cred(
            self.project,
            status=P,
            window_expires_at=NOW + timedelta(seconds=10),
        )
        reap = cred(
            self.bobs_project,
            status=P,
            window_expires_at=NOW - timedelta(seconds=1),
        )

        output = self.run_command()

        keep.refresh_from_db()
        reap.refresh_from_db()
        self.assertEqual(keep.status, P)
        self.assertEqual(reap.status, I)
        self.assertEqual(reap.invalid_reason, WINDOW)
        self.assertIn("Invalidated 1 previous key(s)", output)

    def test_it_invalidates_current_keys_past_grace(self) -> None:
        still_in_grace = cred(self.project, expires_at=NOW - timedelta(seconds=50))
        past_grace = cred(self.bobs_project, expires_at=NOW - timedelta(seconds=101))

        self.run_command()

        still_in_grace.refresh_from_db()
        past_grace.refresh_from_db()
        self.assertEqual(still_in_grace.status, C)
        self.assertEqual(past_grace.status, I)
        self.assertEqual(past_grace.invalid_reason, EXPIRED)

    def test_it_prunes_audits_by_retention_boundary(self) -> None:
        old = audit(self.project, created_at=NOW - timedelta(seconds=1001))
        fresh = audit(self.project, created_at=NOW - timedelta(seconds=999))

        self.run_command()

        self.assertFalse(ApiKeyAudit.objects.filter(pk=old.pk).exists())
        self.assertTrue(ApiKeyAudit.objects.filter(pk=fresh.pk).exists())

    def test_it_is_idempotent(self) -> None:
        cred(self.bobs_project, status=P, window_expires_at=NOW)
        audit(self.project, created_at=NOW - timedelta(days=99))

        first = self.run_command()
        second = self.run_command()

        self.assertIn("Invalidated 1 previous key(s)", first)
        self.assertIn("Invalidated 0 previous key(s)", second)
        self.assertIn("Invalidated 0 current key(s)", second)
        self.assertIn("Pruned 0 API key audit record(s)", second)

    def test_invalidated_credentials_reject_calls(self) -> None:
        key = self.project.create_api_credential(RW)
        self.project.start_key_rotation(RW)
        ApiKeyCredential.objects.filter(status=P).update(
            status=I, invalid_reason=WINDOW, window_expires_at=NOW
        )

        r = self.client.get("/api/v1/checks/", HTTP_X_API_KEY=key)
        self.assertEqual(r.status_code, 401)

    @override_settings(API_KEY_EXPIRATION_ENABLED=False)
    def test_it_skips_expiry_step_when_expiry_disabled(self) -> None:
        past = cred(self.project, expires_at=NOW - timedelta(days=99))
        self.run_command()
        past.refresh_from_db()
        self.assertEqual(past.status, C)

    @override_settings(
        API_KEY_ROTATION_ENABLED=False,
        API_KEY_EXPIRATION_ENABLED=False,
        API_KEY_AUDIT_RETENTION=0,
    )
    def test_it_tolerates_bad_retention_when_governance_disabled(self) -> None:
        out = StringIO()
        # Must not raise on the non-positive retention setting
        call_command("pruneapikeys", stdout=out)
        self.assertIn("Pruned 0", out.getvalue())
