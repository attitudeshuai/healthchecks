from __future__ import annotations

from hc.api.models import RateLimitConfig
from hc.test import BaseTestCase

ADD_URL = "/admin/api/ratelimitconfig/add/"
CHANGE_URL = "/admin/api/ratelimitconfig/1/change/"


class RateLimitConfigAdminTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice.is_staff = True
        self.alice.is_superuser = True
        self.alice.save()
        self.client.login(username="alice@example.org", password="password")

    def test_it_rejects_zero_window_and_keeps_state_empty(self) -> None:
        r = self.client.post(
            ADD_URL, {"scope": "project", "limit": "10", "window_secs": "0"}
        )
        # The admin form re-renders with field errors instead of saving:
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "window duration")
        self.assertEqual(RateLimitConfig.objects.count(), 0)

    def test_it_rejects_negative_limit(self) -> None:
        r = self.client.post(
            ADD_URL, {"scope": "project", "limit": "-5", "window_secs": "60"}
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(RateLimitConfig.objects.count(), 0)

    def test_it_saves_valid_configuration(self) -> None:
        r = self.client.post(
            ADD_URL, {"scope": "account", "limit": "20", "window_secs": "120"}
        )
        self.assertEqual(r.status_code, 302)

        cfg = RateLimitConfig.load()
        assert cfg is not None
        self.assertEqual(cfg.scope, "account")
        self.assertEqual(cfg.limit, 20)
        self.assertEqual(cfg.window_secs, 120)
        self.assertTrue(cfg.is_configured)

    def test_invalid_update_preserves_previous_configuration(self) -> None:
        self.client.post(
            ADD_URL, {"scope": "project", "limit": "20", "window_secs": "120"}
        )

        r = self.client.post(
            CHANGE_URL, {"scope": "team", "limit": "1", "window_secs": "0"}
        )
        self.assertEqual(r.status_code, 200)  # form errors, not saved

        cfg = RateLimitConfig.load()
        assert cfg is not None
        self.assertEqual((cfg.scope, cfg.limit, cfg.window_secs), ("project", 20, 120))

    def test_blank_configuration_is_allowed(self) -> None:
        # All blank means "fall back to the config-file setting":
        r = self.client.post(ADD_URL, {"scope": "", "limit": "", "window_secs": ""})
        self.assertEqual(r.status_code, 302)
        cfg = RateLimitConfig.load()
        assert cfg is not None
        self.assertFalse(cfg.is_configured)

    def test_singleton_cannot_be_added_twice(self) -> None:
        self.client.post(
            ADD_URL, {"scope": "project", "limit": "20", "window_secs": "120"}
        )
        # Once the singleton exists, the add page is gone:
        r = self.client.get(ADD_URL)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(RateLimitConfig.objects.count(), 1)
