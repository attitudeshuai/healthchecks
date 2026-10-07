from __future__ import annotations

from datetime import datetime, timezone

import time_machine
from django.test.utils import override_settings

from hc.api.models import Check
from hc.test import BaseTestCase

FROZEN = datetime(2020, 1, 1, tzinfo=timezone.utc)


@override_settings(WRITE_RATE_LIMIT=("project", 1, 60))
@time_machine.travel(FROZEN, tick=False)
class FrontWriteRateLimitTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.login(username="alice@example.org", password="password")
        self.add_url = f"/projects/{self.project.code}/checks/add/"
        self.payload = {
            "name": "Test",
            "slug": "test",
            "tags": "",
            "kind": "simple",
            "timeout": "120",
            "grace": "60",
            "tz": "UTC",
        }

    def test_it_limits_consecutive_writes(self) -> None:
        r1 = self.client.post(self.add_url, self.payload)
        self.assertEqual(r1.status_code, 302)

        r2 = self.client.post(self.add_url, self.payload)
        self.assertEqual(r2.status_code, 429)
        self.assertEqual(r2["Retry-After"], "60")
        self.assertIn(b"rate limit", r2.content)

        self.assertEqual(Check.objects.count(), 1)

    def test_it_does_not_limit_reads(self) -> None:
        self.client.post(self.add_url, self.payload)
        # The window is now full, but reading pages keeps working:
        r = self.client.get(f"/projects/{self.project.code}/checks/")
        self.assertEqual(r.status_code, 200)
        r = self.client.get(f"/projects/{self.project.code}/integrations/")
        self.assertEqual(r.status_code, 200)

    def test_it_limits_pause_then_resume(self) -> None:
        check = Check.objects.create(project=self.project, status="up")
        pause_url = f"/checks/{check.code}/pause/"
        resume_url = f"/checks/{check.code}/resume/"

        r = self.client.post(pause_url)
        self.assertEqual(r.status_code, 302)

        r = self.client.post(resume_url)
        self.assertEqual(r.status_code, 429)
        self.assertIn(b"retry in", r.content)

    def test_get_form_render_is_not_limited(self) -> None:
        # Fill the single slot with an unrelated write:
        self.client.post(self.add_url, self.payload)
        # Rendering a check's detail page (a read) stays available:
        check = Check.objects.get()
        r = self.client.get(f"/checks/{check.code}/details/")
        self.assertEqual(r.status_code, 200)


class FrontRateLimitDisabledTestCase(BaseTestCase):
    def test_unconfigured_writes_work_as_before(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        url = f"/projects/{self.project.code}/checks/add/"
        payload = {
            "name": "Test",
            "slug": "test",
            "tags": "",
            "kind": "simple",
            "timeout": "120",
            "grace": "60",
            "tz": "UTC",
        }
        for _ in range(3):
            r = self.client.post(url, payload)
            self.assertEqual(r.status_code, 302)

        self.assertEqual(Check.objects.count(), 3)
