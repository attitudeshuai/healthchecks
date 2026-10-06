from __future__ import annotations

import importlib

from django.apps import apps as django_apps
from django.db import IntegrityError, transaction

from hc.accounts.models import ApiKeyCredential
from hc.test import BaseTestCase

migration = importlib.import_module(
    "hc.accounts.migrations.0054_apikeygovernance"
)


class ApiKeyCredentialModelTestCase(BaseTestCase):
    def test_it_compares_hashed_key(self) -> None:
        key = self.project.set_api_key()
        self.project.save()
        cred = ApiKeyCredential(
            project=self.project,
            slot=ApiKeyCredential.Slot.RW,
            key_hash=self.project.api_key,
            prefix=self.project.api_key[:8],
        )
        self.assertTrue(cred.compare(key))
        self.assertFalse(cred.compare(key[:-1] + "A"))

    def test_it_compares_legacy_plaintext_key(self) -> None:
        cred = ApiKeyCredential(
            project=self.project,
            slot=ApiKeyCredential.Slot.RW,
            key_hash="X" * 32,
            prefix="",
        )
        self.assertTrue(cred.compare("X" * 32))
        self.assertFalse(cred.compare("Y" * 32))

    def test_it_finds_candidates_by_prefix(self) -> None:
        key = self.project.set_api_key()
        self.project.save()
        ApiKeyCredential.objects.create(
            project=self.project,
            slot=ApiKeyCredential.Slot.RW,
            key_hash=self.project.api_key,
            prefix=self.project.api_key[:8],
        )

        candidates = ApiKeyCredential.objects.candidates_for(key)
        self.assertEqual(candidates.count(), 1)
        candidate = candidates.first()
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertTrue(candidate.compare(key))

    def test_it_finds_legacy_plaintext_candidates(self) -> None:
        ApiKeyCredential.objects.create(
            project=self.project,
            slot=ApiKeyCredential.Slot.RW,
            key_hash="X" * 32,
            prefix="",
        )

        candidates = ApiKeyCredential.objects.candidates_for("X" * 32)
        self.assertEqual(candidates.count(), 1)

    def test_it_rejects_second_current_credential(self) -> None:
        ApiKeyCredential.objects.create(
            project=self.project,
            slot=ApiKeyCredential.Slot.RW,
            key_hash="X" * 32,
            prefix="",
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ApiKeyCredential.objects.create(
                    project=self.project,
                    slot=ApiKeyCredential.Slot.RW,
                    key_hash="Y" * 32,
                    prefix="",
                )

    def test_it_allows_invalid_credentials_alongside_current(self) -> None:
        for value in ("X" * 32, "Y" * 32):
            ApiKeyCredential.objects.create(
                project=self.project,
                slot=ApiKeyCredential.Slot.RW,
                key_hash=value,
                prefix="",
                status=ApiKeyCredential.Status.INVALID,
            )
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=ApiKeyCredential.Slot.RW
            ).count(),
            2,
        )


class ImportExistingKeysMigrationTestCase(BaseTestCase):
    def test_it_imports_hashed_and_plaintext_keys(self) -> None:
        # self.project.api_key is a legacy plain text key ("X" * 32)
        ro_key = self.project.set_api_key_readonly()
        self.project.save()

        migration.import_existing_keys(django_apps, None)

        rw = ApiKeyCredential.objects.get(
            project=self.project, slot=ApiKeyCredential.Slot.RW
        )
        self.assertEqual(rw.status, ApiKeyCredential.Status.CURRENT)
        self.assertEqual(rw.prefix, "")
        self.assertEqual(rw.key_hash, "X" * 32)
        self.assertTrue(rw.compare("X" * 32))
        self.assertIsNotNone(rw.created_at)

        ro = ApiKeyCredential.objects.get(
            project=self.project, slot=ApiKeyCredential.Slot.RO
        )
        self.assertEqual(ro.status, ApiKeyCredential.Status.CURRENT)
        self.assertEqual(ro.prefix, self.project.api_key_readonly[:8])
        self.assertTrue(ro.compare(ro_key))

    def test_it_skips_empty_slots(self) -> None:
        migration.import_existing_keys(django_apps, None)

        # bobs_project has no API keys set
        self.assertFalse(
            ApiKeyCredential.objects.filter(project=self.bobs_project).exists()
        )
