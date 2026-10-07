from __future__ import annotations

import json
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TypeVar

from django.contrib.auth.models import User
from django.db import connections
from django.test import Client, TransactionTestCase
from django.test.utils import override_settings

from hc.accounts.models import Profile, Project
from hc.api.models import Check, RateLimitCounter
from hc.test import TestHttpResponse

T = TypeVar("T")


def _run_concurrently(fn: Callable[[], T], num_threads: int) -> list[T]:
    """Run fn num_threads times, releasing all threads simultaneously."""

    barrier = threading.Barrier(num_threads)
    results: list[T] = []
    results_lock = threading.Lock()

    def worker() -> None:
        try:
            barrier.wait()
            value = fn()
        finally:
            # Each thread uses its own database connection, close it so the
            # test teardown can flush the file-based SQLite database:
            connections.close_all()
        with results_lock:
            results.append(value)

    with ThreadPoolExecutor(max_workers=num_threads) as pool:
        futures: list[Future[None]] = [
            pool.submit(worker) for _ in range(num_threads)
        ]
        for f in futures:
            f.result()  # re-raise any worker exception

    return results


class ConcurrencyTestCase(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice = User(username="alice", email="alice@example.org")
        self.alice.save()

        self.project = Project.objects.create(
            owner=self.alice, api_key="X" * 32, badge_key="alice", ping_key="p" * 22
        )
        self.profile = Profile.objects.create(user=self.alice)

    def _post_create(self) -> tuple[int, bytes]:
        r: TestHttpResponse = Client().post(
            "/api/v1/checks/",
            json.dumps({"api_key": "X" * 32}),
            content_type="application/json",
        )
        return r.status_code, r.content

    def test_concurrent_creates_do_not_overshoot_check_limit(self) -> None:
        self.profile.check_limit = 3
        self.profile.save()

        results = _run_concurrently(self._post_create, 8)
        statuses = [status for status, _ in results]

        self.assertEqual(Check.objects.filter(project=self.project).count(), 3)
        self.assertEqual(sorted(statuses).count(201), 3)
        self.assertEqual(sorted(statuses).count(403), 5)

        # Rejected requests carry an explicit, readable reason:
        for status, body in results:
            if status == 403:
                self.assertIn(b"check quota exhausted", body)

    def test_concurrent_sms_authorizations_do_not_overshoot_limit(self) -> None:
        self.profile.sms_limit = 3
        self.profile.save()

        def authorize() -> bool:
            profile = Profile.objects.get(pk=self.profile.pk)
            return profile.authorize_sms()

        results = _run_concurrently(authorize, 8)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.sms_sent, 3)
        self.assertEqual(results.count(True), 3)
        self.assertEqual(results.count(False), 5)
        self.assertGreaterEqual(self.profile.sms_sent, 0)

    @override_settings(WRITE_RATE_LIMIT=("project", 3, 60))
    def test_concurrent_writes_do_not_overshoot_window(self) -> None:
        self.profile.check_limit = 100
        self.profile.save()

        results = _run_concurrently(self._post_create, 8)
        statuses = [status for status, _ in results]

        self.assertEqual(sorted(statuses).count(201), 3)
        self.assertEqual(sorted(statuses).count(429), 5)
        self.assertEqual(Check.objects.filter(project=self.project).count(), 3)
        counter = RateLimitCounter.objects.get()
        self.assertEqual(counter.count, 3)

        for status, body in results:
            if status == 429:
                doc = json.loads(body)
                self.assertIn("error", doc)
                self.assertIn(b"rate limit", body)
