from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth.models import User
from django.db import connection
from django.test import TransactionTestCase, override_settings
from django.utils.timezone import now

from hc.accounts.models import ApiKeyAudit, ApiKeyCredential, Project
from hc.test import BaseTestCase, TestHttpResponse

RW = ApiKeyCredential.Slot.RW
RO = ApiKeyCredential.Slot.RO
C = ApiKeyCredential.Status.CURRENT
P = ApiKeyCredential.Status.PREVIOUS
I = ApiKeyCredential.Status.INVALID

G = ApiKeyAudit.Generation
R = ApiKeyAudit.Result
S = ApiKeyAudit.Source

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_ROTATION_WINDOW=3600)
class GovernedAuthTestCase(BaseTestCase):
    def get(self, key: str) -> TestHttpResponse:
        return self.client.get("/api/v1/checks/", HTTP_X_API_KEY=key)

    def post_header(self, key: str) -> TestHttpResponse:
        return self.client.post(
            "/api/v1/checks/",
            {"name": "Foo"},
            content_type="application/json",
            HTTP_X_API_KEY=key,
        )

    def post_body(self, key: str) -> TestHttpResponse:
        return self.client.post(
            "/api/v1/checks/",
            f'{{"api_key": "{key}", "name": "Foo"}}',
            content_type="application/json",
        )

    def audits(self, **kw: Any) -> list[ApiKeyAudit]:
        return list(ApiKeyAudit.objects.filter(**kw).order_by("id"))

    def test_current_rw_key_works_and_is_audited(self) -> None:
        key = self.project.create_api_credential(RW)

        r = self.get(key)
        self.assertEqual(r.status_code, 200)

        cred = ApiKeyCredential.objects.get(slot=RW, status=C)
        self.assertEqual(cred.call_count, 1)
        self.assertIsNotNone(cred.first_used_at)
        self.assertIsNotNone(cred.last_used_at)
        self.assertEqual(cred.last_source, S.HEADER)

        rows = self.audits(project=self.project)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].result, R.ACCEPTED)
        self.assertEqual(rows[0].generation, G.CURRENT)
        self.assertEqual(rows[0].source, S.HEADER)
        self.assertEqual(rows[0].key_prefix, key[4:12])
        self.assertEqual(rows[0].slot, RW)
        # Audit must not contain key material
        self.assertNotIn(key, str(rows[0].__dict__))

    def test_ro_key_passes_read_but_not_write(self) -> None:
        key = self.project.create_api_credential(RO)

        self.assertEqual(self.get(key).status_code, 200)
        r = self.post_header(key)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "wrong api key")

        # The rejected attempt is audited and attributed to the ro slot
        rejected = self.audits(result=R.REJECTED)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0].slot, RO)
        self.assertEqual(rejected[0].key_prefix, key[4:12])

    def test_both_generations_pass_in_rotation_window(self) -> None:
        k1 = self.project.create_api_credential(RW)
        k2 = self.project.start_key_rotation(RW)

        self.assertEqual(self.get(k1).status_code, 200)
        self.assertEqual(self.get(k2).status_code, 200)

        old = ApiKeyCredential.objects.get(slot=RW, status=P)
        new = ApiKeyCredential.objects.get(slot=RW, status=C)
        self.assertEqual(old.call_count, 1)
        self.assertEqual(new.call_count, 1)

        gens = [a.generation for a in self.audits(project=self.project)]
        self.assertEqual(gens, [G.PREVIOUS, G.CURRENT])

    def test_finish_rotation_makes_old_key_expired(self) -> None:
        k1 = self.project.create_api_credential(RW)
        k2 = self.project.start_key_rotation(RW)
        self.project.finish_key_rotation(RW)

        r = self.get(k1)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "api key is expired")
        # The new key keeps working
        self.assertEqual(self.get(k2).status_code, 200)

        rows = self.audits(project=self.project, result=R.REJECTED_EXPIRED)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].generation, G.PREVIOUS)
        self.assertEqual(rows[0].key_prefix, k1[4:12])

    def test_revoke_old_key_makes_it_expired(self) -> None:
        k1 = self.project.create_api_credential(RW)
        k2 = self.project.start_key_rotation(RW)
        self.project.revoke_previous_key(RW)

        r = self.get(k1)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "api key is expired")
        self.assertEqual(self.get(k2).status_code, 200)

    def test_cleanup_invalidated_previous_key_is_expired(self) -> None:
        k1 = self.project.create_api_credential(RW)
        self.project.start_key_rotation(RW)
        # Simulate the prune task marking the window-ended key invalid
        ApiKeyCredential.objects.filter(slot=RW, status=P).update(
            status=I,
            invalid_reason=ApiKeyCredential.InvalidReason.WINDOW,
            window_expires_at=T0,
        )

        r = self.get(k1)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "api key is expired")

    def test_revoke_current_rejects_both_keys(self) -> None:
        k1 = self.project.create_api_credential(RW)
        k2 = self.project.start_key_rotation(RW)
        self.project.revoke_current_key(RW)

        self.assertEqual(self.get(k1).status_code, 401)
        self.assertEqual(self.get(k2).status_code, 401)

    def test_unknown_key_is_rejected_and_audited_by_prefix(self) -> None:
        self.project.create_api_credential(RW)
        fake = "hcw_" + "Z" * 28

        r = self.get(fake)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "wrong api key")

        rows = ApiKeyAudit.objects.filter(project=None, result=R.REJECTED)
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows[0].key_prefix, fake[4:12])
        self.assertEqual(rows[0].slot, RW)
        self.assertEqual(rows[0].generation, G.UNKNOWN)

    def test_missing_key_is_rejected_without_audit(self) -> None:
        r = self.client.get("/api/v1/checks/")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "missing api key")
        self.assertEqual(ApiKeyAudit.objects.count(), 0)

    def test_unrecognizable_32_char_key_is_rejected_without_audit(self) -> None:
        self.project.create_api_credential(RW)

        r = self.get("A" * 32)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "wrong api key")
        # No hcw_/hcr_ prefix -> cannot be grouped by prefix, no audit row
        self.assertEqual(ApiKeyAudit.objects.count(), 0)

        # A legacy migrated plaintext key that *does* match still authenticates
        ApiKeyCredential.objects.create(
            project=self.bobs_project, slot=RW, key_hash="B" * 32, prefix=""
        )
        self.assertEqual(self.get("B" * 32).status_code, 200)

    def test_usage_counters_and_source_category(self) -> None:
        key = self.project.create_api_credential(RW)

        self.get(key)
        self.get(key)
        self.post_body(key)

        cred = ApiKeyCredential.objects.get(slot=RW, status=C)
        self.assertEqual(cred.call_count, 3)
        self.assertEqual(cred.last_source, S.BODY)

        sources = [a.source for a in self.audits(project=self.project)]
        self.assertEqual(sources, [S.HEADER, S.HEADER, S.BODY])

    @override_settings(
        API_KEY_EXPIRATION_ENABLED=True, API_KEY_EXPIRATION_GRACE=100
    )
    def test_key_in_grace_is_accepted_and_flagged(self) -> None:
        key = self.project.create_api_credential(RW)
        cred = ApiKeyCredential.objects.get(slot=RW, status=C)
        cred.expires_at = T0
        cred.save()

        with patch("hc.accounts.models.now", return_value=T0 + timedelta(seconds=50)):
            r = self.get(key)

        self.assertEqual(r.status_code, 200)
        rows = self.audits(project=self.project, result=R.ACCEPTED_EXPIRED)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].generation, G.CURRENT)

    @override_settings(
        API_KEY_EXPIRATION_ENABLED=True, API_KEY_EXPIRATION_GRACE=100
    )
    def test_key_past_grace_is_expired(self) -> None:
        key = self.project.create_api_credential(RW)
        cred = ApiKeyCredential.objects.get(slot=RW, status=C)
        cred.expires_at = T0
        cred.save()

        with patch("hc.accounts.models.now", return_value=T0 + timedelta(seconds=100)):
            r = self.get(key)

        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "api key is expired")
        rows = self.audits(project=self.project, result=R.REJECTED_EXPIRED)
        self.assertEqual(len(rows), 1)

    @override_settings(API_KEY_EXPIRATION_ENABLED=False)
    def test_expiry_disabled_means_never_expire(self) -> None:
        key = self.project.create_api_credential(RW)
        cred = ApiKeyCredential.objects.get(slot=RW, status=C)
        cred.expires_at = T0
        cred.save()

        with patch("hc.accounts.models.now", return_value=T0 + timedelta(days=999)):
            self.assertEqual(self.get(key).status_code, 200)

    def test_legacy_plaintext_keys_migrated_from_columns_work(self) -> None:
        # Simulate the post-migration state: credential row with raw key
        ApiKeyCredential.objects.create(
            project=self.project, slot=RW, key_hash="X" * 32, prefix="", status=C
        )
        self.assertEqual(self.get("X" * 32).status_code, 200)
        rows = self.audits(project=self.project, result=R.ACCEPTED)
        self.assertEqual(rows[0].generation, G.CURRENT)

    def test_every_committed_rotation_state_accepts_old_key(self) -> None:
        # State 1: before rotation the old key authenticates as current
        k1 = self.project.create_api_credential(RW)
        self.assertEqual(self.get(k1).status_code, 200)

        # State 2: after commit the old key authenticates as previous while
        # the window is open, the new key as current -- no state rejects both
        k2 = self.project.start_key_rotation(RW)
        self.assertEqual(self.get(k1).status_code, 200)
        self.assertEqual(self.get(k2).status_code, 200)

        old = ApiKeyCredential.objects.get(slot=RW, status=P)
        self.assertTrue(old.window_is_open(now()))

    def test_failed_rotation_rolls_back_without_gap(self) -> None:
        k1 = self.project.create_api_credential(RW)

        def boom(p: Project, slot: str) -> str:
            raise RuntimeError("boom")

        with patch.object(Project, "_new_credential", boom):
            with self.assertRaises(RuntimeError):
                self.project.start_key_rotation(RW)

        # Demotion and insert are one atomic unit: the old key is still current
        self.assertEqual(self.get(k1).status_code, 200)
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW
            ).count(),
            1,
        )
        self.assertEqual(
            ApiKeyCredential.objects.get(
                project=self.project, slot=RW
            ).status,
            C,
        )


@skipUnless(
    connection.vendor in ("postgresql", "mysql"),
    "Row-lock interleaving requires PostgreSQL or MySQL; SQLite serializes "
    "writers without a lock queue. Determinism on SQLite is covered by the "
    "atomicity/state-space tests in GovernedAuthTestCase.",
)
@override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_ROTATION_WINDOW=3600)
class ConcurrentRotationTestCase(TransactionTestCase):
    """Deterministic interleave of an in-flight rotation and an auth call.

    A request arriving while the rotation transaction holds the credential
    locks must resolve (after the transaction commits) against the previous
    key inside its open window -- never against neither key.
    """

    def setUp(self) -> None:
        super().setUp()
        self.alice = User(username="alice", email="alice@example.org")
        self.alice.set_password("password")
        self.alice.save()
        self.project = Project.objects.create(
            owner=self.alice, api_key="X" * 32, badge_key="alice"
        )
        self.k1 = self.project.create_api_credential(RW)

    def test_request_during_rotation_commits_against_previous_key(self) -> None:
        from django.db import connection
        from django.test import Client

        demotion_done = threading.Event()
        request_begun = threading.Event()
        allow_commit = threading.Event()
        holder: list[int] = []

        original_new = Project._new_credential

        def paused_new_credential(
            p: Project, slot: str
        ) -> tuple[ApiKeyCredential, str]:
            # Called with the rotation transaction open: old key is already
            # demoted (locks held), new key not yet inserted.
            demotion_done.set()
            allow_commit.wait(10)
            return original_new(p, slot)

        def call_during_rotation() -> None:
            demotion_done.wait(10)
            client = Client()
            request_begun.set()
            r = client.get("/api/v1/checks/", HTTP_X_API_KEY=self.k1)
            holder.append(r.status_code)
            connection.close()

        k2_holder: list[str] = []

        def do_rotation() -> None:
            with patch.object(Project, "_new_credential", paused_new_credential):
                k2_holder.append(self.project.start_key_rotation(RW))
            connection.close()

        rot = threading.Thread(target=do_rotation)
        req = threading.Thread(target=call_during_rotation)
        rot.start()
        self.assertTrue(demotion_done.wait(10))
        req.start()
        self.assertTrue(request_begun.wait(10))
        # Give the request time to reach the locked credential rows
        self._sleep(0.2)
        allow_commit.set()
        rot.join(timeout=10)
        req.join(timeout=10)

        self.assertFalse(rot.is_alive())
        self.assertFalse(req.is_alive())
        k2 = k2_holder[0]
        # The in-flight request was not rejected: after the rotation committed
        # it resolved against the previous key inside the open window
        self.assertEqual(holder, [200])

        client = Client()
        self.assertEqual(
            client.get("/api/v1/checks/", HTTP_X_API_KEY=k2).status_code, 200
        )

        old = ApiKeyCredential.objects.get(project=self.project, slot=RW, status=P)
        new = ApiKeyCredential.objects.get(project=self.project, slot=RW, status=C)
        self.assertEqual(old.call_count, 1)
        self.assertEqual(new.call_count, 1)
        self.assertEqual(
            ApiKeyAudit.objects.get(
                project=self.project, result=R.ACCEPTED, generation=G.PREVIOUS
            ).key_prefix,
            self.k1[4:12],
        )

    def _sleep(self, seconds: float) -> None:
        import time

        time.sleep(seconds)

