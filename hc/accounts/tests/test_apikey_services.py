from __future__ import annotations

from datetime import datetime, timezone
from datetime import timedelta as td
from typing import Any
from unittest.mock import patch

from django.test.utils import override_settings

from hc.accounts.models import (
    ApiKeyCredential,
    ApiKeyError,
    NoCurrentKeyError,
    Project,
    RotationInProgressError,
)
from hc.test import BaseTestCase

RW = ApiKeyCredential.Slot.RW
RO = ApiKeyCredential.Slot.RO
C = ApiKeyCredential.Status.CURRENT
P = ApiKeyCredential.Status.PREVIOUS
I = ApiKeyCredential.Status.INVALID

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _credential(
    project: Project, slot: str = RW, status: str = C, **kw: Any
) -> ApiKeyCredential:
    return ApiKeyCredential.objects.create(
        project=project, slot=slot, key_hash="X" * 32, prefix="", status=status, **kw
    )


@override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_ROTATION_WINDOW=3600)
class KeyLifecycleTestCase(BaseTestCase):
    def test_create_credential_sets_current_and_syncs_column(self) -> None:
        key = self.project.create_api_credential(RW)

        self.assertEqual(len(key), 32)
        self.assertTrue(key.startswith("hcw_"))

        cred = ApiKeyCredential.objects.get(project=self.project, slot=RW, status=C)
        self.assertEqual(cred.prefix, key[4:12])
        self.assertTrue(cred.compare(key))
        self.assertIsNone(cred.expires_at)
        self.assertEqual(self.project.api_key, cred.key_hash)

        # Creating a second current key is rejected
        with self.assertRaises(ApiKeyError):
            self.project.create_api_credential(RW)

    @override_settings(
        API_KEY_EXPIRATION_ENABLED=True, API_KEY_LIFETIME=100
    )
    def test_create_sets_expiry_when_enabled(self) -> None:
        with patch("hc.accounts.models.now", return_value=T0):
            self.project.create_api_credential(RW)
        cred = ApiKeyCredential.objects.get(project=self.project, slot=RW, status=C)
        self.assertEqual(cred.expires_at, T0 + td(seconds=100))

    def test_rotation_demotes_current_and_creates_new(self) -> None:
        with patch("hc.accounts.models.now", return_value=T0):
            k1 = self.project.create_api_credential(RW)
            k2 = self.project.start_key_rotation(RW)

        self.assertNotEqual(k1, k2)
        old = ApiKeyCredential.objects.get(project=self.project, slot=RW, status=P)
        self.assertTrue(old.compare(k1))
        self.assertEqual(old.window_expires_at, T0 + td(seconds=3600))

        new = ApiKeyCredential.objects.get(project=self.project, slot=RW, status=C)
        self.assertTrue(new.compare(k2))
        self.assertEqual(self.project.api_key, new.key_hash)

    def test_double_rotation_is_rejected_without_third_key(self) -> None:
        k1 = self.project.create_api_credential(RW)
        self.project.start_key_rotation(RW)

        hashes = set(
            ApiKeyCredential.objects.filter(project=self.project, slot=RW).values_list(
                "key_hash", flat=True
            )
        )
        with self.assertRaises(RotationInProgressError):
            self.project.start_key_rotation(RW)

        rows = ApiKeyCredential.objects.filter(project=self.project, slot=RW)
        self.assertEqual(rows.count(), 2)
        self.assertEqual(
            set(rows.values_list("status", flat=True)),
            {C, P},
        )
        self.assertEqual(
            set(rows.values_list("key_hash", flat=True)), hashes
        )
        self.assertTrue(k1)  # k1 is retained as the previous key

    def test_rotation_without_current_key_raises(self) -> None:
        with self.assertRaises(NoCurrentKeyError):
            self.project.start_key_rotation(RW)

    def test_finish_rotation_invalidates_previous(self) -> None:
        self.project.create_api_credential(RW)
        self.project.start_key_rotation(RW)

        self.assertTrue(self.project.finish_key_rotation(RW))
        self.assertFalse(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=P
            ).exists()
        )
        # Idempotent: nothing to finish the second time
        self.assertFalse(self.project.finish_key_rotation(RW))

    def test_revoke_previous_invalidates_previous(self) -> None:
        self.project.create_api_credential(RW)
        self.project.start_key_rotation(RW)

        self.assertTrue(self.project.revoke_previous_key(RW))
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=I
            ).count(),
            1,
        )
        # The current key is untouched
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=C
            ).count(),
            1,
        )

    def test_revoke_current_takes_previous_too_and_allows_regeneration(self) -> None:
        self.project.create_api_credential(RW)
        self.project.start_key_rotation(RW)

        self.project.revoke_current_key(RW)

        self.assertFalse(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status__in=(C, P)
            ).exists()
        )
        self.assertEqual(self.project.api_key, "")

        k3 = self.project.create_api_credential(RW)
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=C
            ).count(),
            1,
        )
        self.assertTrue(
            ApiKeyCredential.objects.get(
                project=self.project, slot=RW, status=C
            ).compare(k3)
        )

    def test_readonly_slot_rotation(self) -> None:
        k1 = self.project.create_api_credential(RO)
        self.assertTrue(k1.startswith("hcr_"))

        k2 = self.project.start_key_rotation(RO)
        self.assertTrue(k2.startswith("hcr_"))
        self.assertEqual(self.project.api_key_readonly[:8], k2[4:12])


@override_settings(
    API_KEY_ROTATION_ENABLED=True,
    API_KEY_EXPIRATION_ENABLED=True,
    API_KEY_ROTATION_WINDOW=3600,
    API_KEY_EXPIRATION_GRACE=100,
)
class CredentialEvaluationTestCase(BaseTestCase):
    def test_current_key_before_expiry_is_valid(self) -> None:
        cred = _credential(self.project, expires_at=T0 + td(seconds=100))
        self.assertEqual(cred.evaluate(T0), "valid")

    def test_current_key_in_grace_is_grace(self) -> None:
        cred = _credential(self.project, expires_at=T0)
        self.assertEqual(cred.evaluate(T0 + td(seconds=50)), "grace")

    def test_current_key_past_grace_is_expired(self) -> None:
        cred = _credential(self.project, expires_at=T0)
        self.assertEqual(cred.evaluate(T0 + td(seconds=100)), "expired")

    def test_previous_within_window_is_valid(self) -> None:
        cred = _credential(
            self.project, status=P, window_expires_at=T0 + td(seconds=3600)
        )
        self.assertEqual(cred.evaluate(T0 + td(seconds=100)), "valid")

    def test_previous_after_window_is_expired(self) -> None:
        cred = _credential(
            self.project, status=P, window_expires_at=T0 + td(seconds=3600)
        )
        self.assertEqual(cred.evaluate(T0 + td(seconds=3600)), "expired")

    def test_previous_in_window_but_past_expiry_grace_is_expired(self) -> None:
        cred = _credential(
            self.project,
            status=P,
            window_expires_at=T0 + td(seconds=3600),
            expires_at=T0,
        )
        self.assertEqual(cred.evaluate(T0 + td(seconds=200)), "expired")

    @override_settings(API_KEY_EXPIRATION_ENABLED=False)
    def test_expiry_disabled_ignores_expires_at(self) -> None:
        cred = _credential(self.project, expires_at=T0)
        self.assertEqual(cred.evaluate(T0 + td(seconds=9999)), "valid")
