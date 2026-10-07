from __future__ import annotations

import json
from datetime import datetime, timezone

import time_machine
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from hc.accounts.models import Project
from hc.api.middleware import WriteRateLimitMiddleware
from hc.api.models import Check, RateLimitConfig, RateLimitCounter
from hc.api.ratelimit import (
    InvalidRateLimitConfig,
    RateLimitExceeded,
    WindowState,
    enforce_write_rate_limit,
    get_active_config,
)
from hc.test import BaseTestCase, TestHttpResponse

FROZEN = datetime(2020, 1, 1, tzinfo=timezone.utc)
PROJECT_LIMIT = ("project", 2, 60)
ACCOUNT_LIMIT = ("account", 3, 60)


class WriteRateLimitDisabledTestCase(BaseTestCase):
    """Without configuration, behavior must be identical to before."""

    def test_writes_have_no_rate_limit_headers(self) -> None:
        r = self.client.post(
            "/api/v3/checks/",
            json.dumps({"api_key": "X" * 32}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201)
        self.assertNotIn("X-RateLimit-Limit", r)
        self.assertNotIn("Retry-After", r)
        self.assertEqual(RateLimitCounter.objects.count(), 0)

    def test_status_reports_disabled(self) -> None:
        r = self.client.get("/api/v3/rate_limit/", HTTP_X_API_KEY="X" * 32)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"enabled": False})


@override_settings(WRITE_RATE_LIMIT=PROJECT_LIMIT)
@time_machine.travel(FROZEN, tick=False)
class ProjectScopeTestCase(BaseTestCase):
    def post_create(self) -> TestHttpResponse:
        return self.client.post(
            "/api/v3/checks/",
            json.dumps({"api_key": "X" * 32}),
            content_type="application/json",
        )

    def test_it_allows_up_to_limit(self) -> None:
        r1 = self.post_create()
        self.assertEqual(r1.status_code, 201)
        self.assertEqual(r1["X-RateLimit-Limit"], "2")
        self.assertEqual(r1["X-RateLimit-Remaining"], "1")

        r2 = self.post_create()
        self.assertEqual(r2.status_code, 201)
        self.assertEqual(r2["X-RateLimit-Remaining"], "0")

    def test_it_rejects_over_limit_with_error_shape(self) -> None:
        self.post_create()
        self.post_create()
        r = self.post_create()

        self.assertEqual(r.status_code, 429)
        # Same error envelope as other API errors:
        self.assertIn("error", r.json())
        self.assertIn("rate limit", r.json()["error"])
        self.assertIn("seconds", r.json()["error"])
        self.assertEqual(r["Retry-After"], "60")
        self.assertEqual(r["X-RateLimit-Remaining"], "0")
        # The rejected request did not create anything and did not over-count:
        self.assertEqual(Check.objects.count(), 2)
        counter = RateLimitCounter.objects.get()
        self.assertEqual(counter.count, 2)

    def test_window_rolls_over(self) -> None:
        self.post_create()
        self.post_create()
        self.assertEqual(self.post_create().status_code, 429)

        new_window = datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc)
        with time_machine.travel(new_window, tick=False):
            r = self.post_create()
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r["X-RateLimit-Remaining"], "1")

        # The fresh window starts a new counter; previous windows for the same
        # bucket are pruned by the first request in the new window:
        counter = RateLimitCounter.objects.get()
        self.assertEqual(counter.count, 1)
        self.assertEqual(counter.window_start, new_window)

    def post_empty(self, url: str) -> TestHttpResponse:
        return self.client.post(
            url,
            "",
            content_type="application/json",
            HTTP_X_API_KEY="X" * 32,
        )

    def test_other_write_endpoints_are_limited(self) -> None:
        check = Check.objects.create(project=self.project, status="up")
        url = f"/api/v3/checks/{check.code}/pause"

        first = self.post_empty(url)
        self.assertEqual(first.status_code, 200)
        second = self.post_empty(url)
        self.assertEqual(second.status_code, 200)  # already paused, still a write

        third = self.post_empty(f"/api/v3/checks/{check.code}/resume")
        self.assertEqual(third.status_code, 429)

    def test_reads_are_not_limited(self) -> None:
        self.post_create()
        self.post_create()

        # Listing checks, reading pings and CORS preflight stay available:
        r = self.client.get("/api/v3/checks/", HTTP_X_API_KEY="X" * 32)
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("X-RateLimit-Limit", r)

        r = self.client.options("/api/v3/checks/")
        self.assertEqual(r.status_code, 204)

        # A read-only key keeps working as well:
        self.project.api_key_readonly = "R" * 32
        self.project.save()
        r = self.client.get("/api/v3/checks/", HTTP_X_API_KEY="R" * 32)
        self.assertEqual(r.status_code, 200)

    def test_inbound_pings_are_not_limited(self) -> None:
        check = Check.objects.create(project=self.project, status="up")
        # Exhaust the write window entirely:
        self.post_create()
        self.post_create()
        self.assertEqual(self.post_create().status_code, 429)

        # Inbound signals keep flowing:
        for _ in range(5):
            r = self.client.post(f"/ping/{check.code}")
            self.assertEqual(r.status_code, 200)

    def test_status_endpoint_reports_window_without_consuming(self) -> None:
        self.post_create()

        r = self.client.get("/api/v3/rate_limit/", HTTP_X_API_KEY="X" * 32)
        doc = r.json()
        self.assertTrue(doc["enabled"])
        self.assertEqual(doc["scope"], "project")
        self.assertEqual(doc["limit"], 2)
        self.assertEqual(doc["used"], 1)
        self.assertEqual(doc["remaining"], 1)
        self.assertEqual(doc["window_secs"], 60)
        self.assertTrue(doc["window_end"].startswith("2020-01-01T00:01:00"))
        self.assertEqual(doc["retry_after"], 60)

        # Read-only keys may read the status too:
        self.project.api_key_readonly = "R" * 32
        self.project.save()
        r = self.client.get("/api/v3/rate_limit/", HTTP_X_API_KEY="R" * 32)
        self.assertEqual(r.status_code, 200)

        # Two status calls did not consume slots:
        r = self.client.get("/api/v3/rate_limit/", HTTP_X_API_KEY="X" * 32)
        self.assertEqual(r.json()["used"], 1)

        self.post_create()
        self.assertEqual(self.post_create().status_code, 429)


@override_settings(WRITE_RATE_LIMIT=ACCOUNT_LIMIT)
@time_machine.travel(FROZEN, tick=False)
class AccountScopeTestCase(BaseTestCase):
    def test_projects_of_same_owner_share_bucket(self) -> None:
        second = Project.objects.create(owner=self.alice, badge_key="alice-2")
        second_key = second.set_api_key()
        second.save()

        def post(key: str) -> TestHttpResponse:
            return self.client.post(
                "/api/v3/checks/",
                json.dumps({}),
                content_type="application/json",
                HTTP_X_API_KEY=key,
            )

        # Two writes against the first project:
        self.assertEqual(post("X" * 32).status_code, 201)
        self.assertEqual(post("X" * 32).status_code, 201)
        # The third allowed slot is used against the second project:
        self.assertEqual(post(second_key).status_code, 201)
        # The fourth write, again against the second project, shares the
        # account-scoped bucket and is rejected:
        self.assertEqual(post(second_key).status_code, 429)

    def test_different_accounts_have_independent_buckets(self) -> None:
        # Alice's window is full:
        for _ in range(3):
            self.assertEqual(self.post().status_code, 201)
        self.assertEqual(self.post().status_code, 429)

        # Bob's account is unaffected:
        key = self.bobs_project.set_api_key()
        self.bobs_project.save()
        r = self.client.post(
            "/api/v3/checks/",
            json.dumps({}),
            content_type="application/json",
            HTTP_X_API_KEY=key,
        )
        self.assertEqual(r.status_code, 201)

    def post(self) -> TestHttpResponse:
        return self.client.post(
            "/api/v3/checks/",
            json.dumps({}),
            content_type="application/json",
            HTTP_X_API_KEY="X" * 32,
        )


class ConfigResolutionTestCase(BaseTestCase):
    def test_invalid_settings_raise_explicit_error(self) -> None:
        for bad in (("team", 10, 60), ("project", -1, 60), ("project", 10, 0)):
            with override_settings(WRITE_RATE_LIMIT=bad):
                with self.assertRaises(ImproperlyConfigured):
                    get_active_config()
                with self.assertRaises(ImproperlyConfigured):
                    enforce_write_rate_limit(self.project)

    def test_database_config_takes_precedence(self) -> None:
        # No setting configured in this test:
        cfg = RateLimitConfig(
            scope="project", limit=1, window_secs=60
        )
        cfg.full_clean()
        cfg.save()

        self.assertEqual(get_active_config(), ("project", 1, 60))

        r = self.client.post(
            "/api/v3/checks/",
            json.dumps({"api_key": "X" * 32}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201)
        r = self.client.post(
            "/api/v3/checks/",
            json.dumps({"api_key": "X" * 32}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 429)

    def test_blank_database_row_falls_back_to_setting(self) -> None:
        RateLimitConfig().save()  # all-blank singleton

        with override_settings(WRITE_RATE_LIMIT=("account", 5, 30)):
            self.assertEqual(get_active_config(), ("account", 5, 30))

    def test_one_request_consumes_at_most_one_slot(self) -> None:
        # A request may touch several project/check access helpers, but it
        # must be counted once:
        request = RequestFactory().post("/api/v3/checks/")
        with override_settings(WRITE_RATE_LIMIT=("project", 2, 60)):
            first = enforce_write_rate_limit(self.project, request)
            second = enforce_write_rate_limit(self.project, request)

        assert first is not None and second is not None
        self.assertEqual(first.used, 1)
        self.assertEqual(second.used, 1)
        self.assertEqual(RateLimitCounter.objects.get().count, 1)

    def test_invalid_database_row_raises_on_write(self) -> None:
        # Unknown scope is not DB-constrained, so this row can only exist if
        # validation was bypassed:
        bad = RateLimitConfig(scope="team", limit=10, window_secs=60)
        bad.save()

        with self.assertRaises(InvalidRateLimitConfig):
            get_active_config()
        with self.assertRaises(InvalidRateLimitConfig):
            enforce_write_rate_limit(self.project)

    def test_model_validation_rejects_bad_values(self) -> None:
        from django.core.exceptions import ValidationError

        for kwargs in (
            {"scope": "team", "limit": 10, "window_secs": 60},
            {"scope": "project", "limit": -1, "window_secs": 60},
            {"scope": "project", "limit": 10, "window_secs": 0},
            {"scope": "project", "limit": None, "window_secs": 60},
        ):
            with self.assertRaises(ValidationError):
                RateLimitConfig(**kwargs).full_clean()

        # All blank is valid (means "fall back to settings"):
        RateLimitConfig().full_clean()
        # A zero limit (deny all writes) is itself a valid configuration:
        RateLimitConfig(scope="account", limit=0, window_secs=1).full_clean()


class RateLimitMiddlewareTestCase(BaseTestCase):
    def _state(self) -> WindowState:
        return WindowState(
            scope="project",
            limit=1,
            window_secs=60,
            used=1,
            window_start=FROZEN,
            window_end=datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc),
        )

    def _mw(self) -> WriteRateLimitMiddleware:
        return WriteRateLimitMiddleware(lambda request: HttpResponse())

    def test_api_paths_get_json_envelope(self) -> None:
        request = RequestFactory().post("/api/v3/checks/")
        with time_machine.travel(FROZEN, tick=False):
            response = self._mw().process_exception(
                request, RateLimitExceeded(self._state())
            )

        assert response is not None
        self.assertEqual(response.status_code, 429)
        self.assertIn("error", json.loads(response.content))
        self.assertEqual(response["Retry-After"], "60")
        self.assertEqual(response["X-RateLimit-Remaining"], "0")

    def test_front_paths_get_plain_text(self) -> None:
        request = RequestFactory().post("/projects/x/checks/add/")
        with time_machine.travel(FROZEN, tick=False):
            response = self._mw().process_exception(
                request, RateLimitExceeded(self._state())
            )

        assert response is not None
        self.assertEqual(response.status_code, 429)
        self.assertIn("rate limit", response.content.decode())
        self.assertEqual(response["Retry-After"], "60")

    def test_other_exceptions_pass_through(self) -> None:
        response = self._mw().process_exception(
            RequestFactory().get("/"), ValueError("not a rate limit")
        )
        self.assertIsNone(response)
