from __future__ import annotations

from django.test.utils import override_settings

from hc.accounts.models import ApiKeyAudit, ApiKeyCredential
from hc.test import BaseTestCase

RW = ApiKeyCredential.Slot.RW
RO = ApiKeyCredential.Slot.RO
C = ApiKeyCredential.Status.CURRENT
P = ApiKeyCredential.Status.PREVIOUS
I = ApiKeyCredential.Status.INVALID


@override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_ROTATION_WINDOW=3600)
class GovernedProjectSettingsTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.url = f"/projects/{self.project.code}/settings/"
        self.client.login(username="alice@example.org", password="password")
        # Simulate post-migration state: existing hashed key as a credential
        self.rw_key = self.project.set_api_key()
        self.project.save()
        ApiKeyCredential.objects.create(
            project=self.project,
            slot=RW,
            key_hash=self.project.api_key,
            prefix=self.project.api_key[:8],
            status=C,
        )

    def test_page_shows_rotation_entry_and_metadata(self) -> None:
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'data-rotate-key="api_key"')
        self.assertContains(r, "Key Activity &amp; Audit")
        self.assertContains(r, "Calls: 0")

    def test_page_shows_previous_key_and_window_actions(self) -> None:
        self.project.start_key_rotation(RW)

        r = self.client.get(self.url)
        self.assertContains(r, "API key (previous)")
        self.assertContains(r, 'data-finish-key="api_key"')
        self.assertContains(r, 'data-revoke-old-key="api_key"')
        self.assertContains(r, "Rotation window ends")

    def test_rotate_creates_new_key_and_shows_it_once(self) -> None:
        r = self.client.post(self.url, {"rotate_key": "api_key"})
        self.assertEqual(r.status_code, 200)

        rows = ApiKeyCredential.objects.filter(project=self.project, slot=RW)
        self.assertEqual(set(rows.values_list("status", flat=True)), {C, P})
        self.assertContains(r, "key-created-modal")
        self.assertContains(r, "hcw_")

    def test_second_rotation_in_window_returns_explicit_400(self) -> None:
        self.project.start_key_rotation(RW)
        hashes = set(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW
            ).values_list("key_hash", flat=True)
        )

        r = self.client.post(self.url, {"rotate_key": "api_key"})
        self.assertEqual(r.status_code, 400)
        self.assertContains(r, "already in progress", status_code=400)
        self.assertEqual(
            set(
                ApiKeyCredential.objects.filter(
                    project=self.project, slot=RW
                ).values_list("key_hash", flat=True)
            ),
            hashes,
        )

    def test_finish_rotation_invalidates_previous(self) -> None:
        self.project.start_key_rotation(RW)

        r = self.client.post(self.url, {"finish_rotation": "api_key"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=P
            ).exists()
        )

    def test_revoke_old_key_invalidates_previous(self) -> None:
        self.project.start_key_rotation(RW)

        r = self.client.post(self.url, {"revoke_old_key": "api_key"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=I
            ).count(),
            1,
        )

    def test_revoke_current_empties_slot_and_allows_create(self) -> None:
        self.project.start_key_rotation(RW)
        self.client.post(self.url, {"revoke_key": "api_key"})

        self.project.refresh_from_db()
        self.assertEqual(self.project.api_key, "")
        r = self.client.get(self.url)
        self.assertContains(r, 'data-create-key="api_key"')

        r = self.client.post(self.url, {"create_key": "api_key"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            ApiKeyCredential.objects.filter(
                project=self.project, slot=RW, status=C
            ).count(),
            1,
        )

    def test_readonly_member_cannot_rotate(self) -> None:
        self.bobs_membership.role = "r"
        self.bobs_membership.save()
        self.client.login(username="bob@example.org", password="password")

        r = self.client.post(self.url, {"rotate_key": "api_key"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post(self.url, {"finish_rotation": "api_key"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post(self.url, {"revoke_old_key": "api_key"})
        self.assertEqual(r.status_code, 403)

    def test_bad_slot_value_rejected(self) -> None:
        r = self.client.post(self.url, {"rotate_key": "ping_key"})
        self.assertEqual(r.status_code, 400)

    def test_page_lists_audits_and_rejected_prefixes(self) -> None:
        ro = self.project.create_api_credential(RO)
        # An accepted read-only call
        self.client.get("/api/v1/checks/", HTTP_X_API_KEY=ro)

        # A caller still using the old key after the window was ended
        self.project.start_key_rotation(RW)
        self.project.finish_key_rotation(RW)
        self.client.get("/api/v1/checks/", HTTP_X_API_KEY=self.rw_key)

        r = self.client.get(self.url)
        self.assertContains(r, "Accepted")
        self.assertContains(r, "Rejected (expired)")
        self.assertContains(r, "hcw_" + self.rw_key[4:12])
        self.assertContains(r, "Callers still using old or rejected keys")


class GovernanceDisabledProjectSettingsTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.url = f"/projects/{self.project.code}/settings/"
        self.client.login(username="alice@example.org", password="password")

    def test_page_has_no_governance_elements(self) -> None:
        r = self.client.get(self.url)
        self.assertNotContains(r, 'data-rotate-key=')
        self.assertNotContains(r, "Key Activity")
        self.assertNotContains(r, "API key (previous)")
        self.assertNotContains(r, 'id="rotate-key-modal"')
        self.assertNotContains(r, 'id="finish-key-modal"')
        self.assertNotContains(r, 'id="revoke-old-key-modal"')

    def test_rotation_post_is_rejected_when_disabled(self) -> None:
        r = self.client.post(self.url, {"rotate_key": "api_key"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(
            ApiKeyCredential.objects.filter(project=self.project).count(), 0
        )
        self.assertEqual(ApiKeyAudit.objects.count(), 0)
