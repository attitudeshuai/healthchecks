from __future__ import annotations

from datetime import datetime, timezone
from datetime import timedelta as td
from uuid import uuid4

from django.test.utils import override_settings

from hc.api.models import Check, Ping
from hc.api.views import _sign_pings_cursor
from hc.test import BaseTestCase, TestHttpResponse

EPOCH = datetime(2020, 1, 1, tzinfo=timezone.utc)
EPOCH_TS = int(EPOCH.timestamp())


class GetPingsTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.a1 = Check(project=self.project, name="Alice 1")
        self.a1.timeout = td(seconds=3600)
        self.a1.grace = td(seconds=900)
        self.a1.n_pings = 1
        self.a1.status = "new"
        self.a1.tags = "a1-tag a1-additional-tag"
        self.a1.desc = "This is description"
        self.a1.save()

        self.ping = Ping(owner=self.a1)
        self.ping.n = 1
        self.ping.remote_addr = "1.2.3.4"
        self.ping.scheme = "https"
        self.ping.method = "get"
        self.ping.ua = "foo-agent"
        self.ping.save()

        self.url = f"/api/v3/checks/{self.a1.code}/pings/"

    def get(
        self,
        params: dict[str, str | int] | None = None,
        api_key: str = "X" * 32,
    ) -> TestHttpResponse:
        return self.csrf_client.get(
            self.url, data=params, HTTP_X_API_KEY=api_key
        )

    def test_it_works(self) -> None:
        r = self.get()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")

        doc = r.json()
        # With no new parameters the response shape stays exactly as before:
        self.assertEqual(set(doc.keys()), {"pings"})
        self.assertEqual(len(doc["pings"]), 1)

        ping = doc["pings"][0]
        self.assertEqual(ping["n"], 1)
        self.assertEqual(ping["remote_addr"], "1.2.3.4")
        self.assertEqual(ping["scheme"], "https")
        self.assertEqual(ping["method"], "get")
        self.assertEqual(ping["ua"], "foo-agent")
        # body_raw is null, object_size is null, body_url should be None
        self.assertIsNone(ping["body_url"])

    def test_readonly_key_is_allowed(self) -> None:
        self.project.api_key_readonly = "R" * 32
        self.project.save()

        r = self.get(api_key=self.project.api_key_readonly)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()["pings"]), 1)

    def test_readonly_key_cannot_write(self) -> None:
        self.project.api_key_readonly = "R" * 32
        self.project.save()

        r = self.csrf_client.post(self.url, HTTP_X_API_KEY="R" * 32)
        self.assertEqual(r.status_code, 405)

    def test_it_rejects_post(self) -> None:
        r = self.csrf_client.post(self.url, HTTP_X_API_KEY="X" * 32)
        self.assertEqual(r.status_code, 405)

    def test_it_handles_missing_api_key(self) -> None:
        r = self.client.get(self.url)
        self.assertContains(r, "missing api key", status_code=401)

    def test_it_rejects_charlies_key(self) -> None:
        self.charlies_project.api_key = "C" * 32
        self.charlies_project.save()

        r = self.get(params={"count": 1}, api_key="C" * 32)
        self.assertEqual(r.status_code, 403)

    def test_it_handles_missing_check(self) -> None:
        r = self.csrf_client.get(
            f"/api/v3/checks/{uuid4()}/pings/?count=1", HTTP_X_API_KEY="X" * 32
        )
        self.assertEqual(r.status_code, 404)

    def test_it_calculates_overlapping_durations(self) -> None:
        self.ping.delete()

        m = td(minutes=1)
        a, b = uuid4(), uuid4()
        self.a1.ping_set.create(n=1, rid=a, created=EPOCH, kind="start")
        self.a1.ping_set.create(n=2, rid=b, created=EPOCH + m, kind="start")
        self.a1.ping_set.create(n=3, rid=a, created=EPOCH + m * 2)
        self.a1.ping_set.create(n=4, rid=b, created=EPOCH + m * 6)

        with self.assertNumQueries(4):
            doc = self.get().json()
            self.assertEqual(doc["pings"][0]["duration"], 300.0)
            self.assertEqual(doc["pings"][1]["duration"], 120.0)

    def test_it_disables_duration_calculation(self) -> None:
        self.ping.delete()
        # Set up a worst case scenario where each success ping has an unique rid,
        # and there are no "start" pings:
        for i in range(1, 12):
            self.a1.ping_set.create(n=i, rid=uuid4(), created=EPOCH + td(minutes=i))

        # Make sure we don't run Ping.duration() per ping:
        with self.assertNumQueries(4):
            doc = self.get().json()
            for d in doc["pings"]:
                self.assertNotIn("duration", d)

    def test_it_handles_rid(self) -> None:
        self.ping.rid = uuid4()
        self.ping.save()

        doc = self.get().json()
        ping = doc["pings"][0]
        self.assertEqual(ping["rid"], str(self.ping.rid))

    def test_it_handles_empty_body_raw(self) -> None:
        self.ping.body_raw = b""
        self.ping.save()

        doc = self.get().json()
        ping = doc["pings"][0]
        self.assertIsNone(ping["body_url"])

    def test_it_handles_zero_object_size(self) -> None:
        self.ping.object_size = 0
        self.ping.save()

        doc = self.get().json()
        ping = doc["pings"][0]
        self.assertIsNone(ping["body_url"])

    @override_settings(SITE_ROOT="http://testserver")
    def test_it_handles_nonempty_body_raw(self) -> None:
        self.ping.body_raw = b"this is ping body"
        self.ping.save()

        doc = self.get().json()
        ping = doc["pings"][0]
        self.assertEqual(
            ping["body_url"],
            f"http://testserver/api/v3/checks/{self.a1.code}/pings/1/body",
        )

    @override_settings(SITE_ROOT="http://testserver")
    def test_it_handles_nonempty_object_size(self) -> None:
        self.ping.object_size = 123
        self.ping.save()

        doc = self.get().json()
        ping = doc["pings"][0]
        self.assertEqual(
            ping["body_url"],
            f"http://testserver/api/v3/checks/{self.a1.code}/pings/1/body",
        )

    def test_legacy_mode_uses_account_limit(self) -> None:
        # The default ping log limit is 100. Create 101 pings.
        self.ping.delete()
        for i in range(1, 102):
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))

        doc = self.get().json()
        # No extra keys in the legacy response:
        self.assertEqual(set(doc.keys()), {"pings"})
        # The account limit (100) still caps the legacy response:
        self.assertEqual(len(doc["pings"]), 100)

    def test_it_walks_all_pages(self) -> None:
        self.ping.delete()
        for i in range(1, 6):
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))

        seen: list[int] = []
        cursor: str | None = None
        page_count = 0
        while True:
            params: dict[str, str | int] = {"count": 2}
            if cursor:
                params["cursor"] = cursor

            doc = self.get(params).json()
            page_count += 1
            seen.extend(p["n"] for p in doc["pings"])

            if doc["done"]:
                self.assertIsNone(doc["next_cursor"])
                break

            self.assertFalse(doc["done"])
            self.assertIsInstance(doc["next_cursor"], str)
            cursor = doc["next_cursor"]

        # Pings are returned in the descending n order, with no gaps/duplicates:
        self.assertEqual(seen, [5, 4, 3, 2, 1])
        self.assertEqual(len(seen), len(set(seen)))
        # 2 + 2 + 1 = 3 pages:
        self.assertEqual(page_count, 3)

    def test_last_page_is_marked_done_on_single_full_walk(self) -> None:
        doc = self.get({"count": 1}).json()
        self.assertEqual(len(doc["pings"]), 1)
        self.assertTrue(doc["done"])
        self.assertIsNone(doc["next_cursor"])

    def test_count_too_small_is_rejected(self) -> None:
        r = self.get({"count": 0})
        self.assertEqual(r.status_code, 400)
        self.assertIn("count", r.json()["error"])

    def test_count_too_large_is_rejected(self) -> None:
        r = self.get({"count": 1001})
        self.assertEqual(r.status_code, 400)
        self.assertIn("count", r.json()["error"])

    def test_count_non_integer_is_rejected(self) -> None:
        r = self.get({"count": "abc"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("count", r.json()["error"])

    def test_count_is_not_silently_capped_by_account_limit(self) -> None:
        # The default ping log limit is 100, but explicit page sizes must be
        # governed solely by the 1..1000 bounds:
        self.ping.delete()
        for i in range(1, 1002):
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))

        doc = self.get({"count": 1000}).json()
        self.assertEqual(len(doc["pings"]), 1000)
        self.assertFalse(doc["done"])
        self.assertIsNotNone(doc["next_cursor"])

    def test_default_page_size_is_100(self) -> None:
        self.ping.delete()
        for i in range(1, 102):
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))

        # Supplying a time-window parameter enables the paginated mode,
        # and the default page size is 100:
        doc = self.get({"start": 0}).json()
        self.assertEqual(len(doc["pings"]), 100)
        self.assertFalse(doc["done"])

    def test_new_writes_do_not_shift_pages(self) -> None:
        self.ping.delete()
        for i in range(1, 5):
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))

        doc = self.get({"count": 2}).json()
        self.assertEqual([p["n"] for p in doc["pings"]], [4, 3])
        cursor = doc["next_cursor"]

        # A new ping arrives while the caller is paging:
        self.a1.ping_set.create(n=5, created=EPOCH + td(minutes=5))

        # The already-issued position is unaffected: no dup, no shift:
        doc = self.get({"count": 2, "cursor": cursor}).json()
        self.assertEqual([p["n"] for p in doc["pings"]], [2, 1])
        self.assertTrue(doc["done"])

    def test_tampered_cursor_is_rejected(self) -> None:
        for token in ("garbage", "a:b.c", "deadbeef:123.sig"):
            r = self.get({"cursor": token})
            self.assertEqual(r.status_code, 400, token)
            self.assertIn("cursor", r.json()["error"], token)

    def test_mutated_cursor_signature_is_rejected(self) -> None:
        self.a1.ping_set.create(n=2, created=EPOCH + td(minutes=2))

        doc = self.get({"count": 1}).json()
        cursor = doc["next_cursor"]
        self.assertIsNotNone(cursor)
        # Flip the final character of the signature:
        mutated = cursor[:-1] + ("a" if cursor[-1] != "a" else "b")
        r = self.get({"cursor": mutated})
        self.assertEqual(r.status_code, 400)

    def test_cursor_from_another_check_is_rejected(self) -> None:
        other = Check.objects.create(project=self.project)
        other_ping = Ping.objects.create(owner=other)
        token = _sign_pings_cursor(other.code, other_ping.id)

        r = self.get({"cursor": token})
        self.assertEqual(r.status_code, 400)
        self.assertIn("cursor", r.json()["error"])

    def test_stale_cursor_is_reported_not_as_empty_page(self) -> None:
        self.ping.delete()
        pings = [
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))
            for i in range(1, 4)
        ]

        doc = self.get({"count": 2}).json()
        self.assertEqual([p["n"] for p in doc["pings"]], [3, 2])
        cursor = doc["next_cursor"]

        # Simulate the retention policy pruning the ping the cursor points at:
        pings[1].delete()

        r = self.get({"cursor": cursor})
        self.assertEqual(r.status_code, 409)
        self.assertIn("cursor", r.json()["error"])

        # Restarting without a cursor works from the current earliest row:
        doc = self.get({"count": 10}).json()
        self.assertEqual([p["n"] for p in doc["pings"]], [3, 1])
        self.assertTrue(doc["done"])

    def test_time_window_filters_in_descending_n_order(self) -> None:
        self.ping.delete()
        for i in range(1, 6):
            self.a1.ping_set.create(n=i, created=EPOCH + td(minutes=i))

        # start is inclusive, end is exclusive:
        start = EPOCH_TS + 60 * 2
        end = EPOCH_TS + 60 * 4
        doc = self.get({"count": 10, "start": start, "end": end}).json()
        self.assertEqual([p["n"] for p in doc["pings"]], [3, 2])
        self.assertTrue(doc["done"])

    def test_start_equal_end_returns_empty(self) -> None:
        doc = self.get({"start": EPOCH_TS, "end": EPOCH_TS}).json()
        self.assertEqual(doc["pings"], [])
        self.assertTrue(doc["done"])
        self.assertIsNone(doc["next_cursor"])

    def test_empty_window_returns_empty_not_error(self) -> None:
        doc = self.get({"start": EPOCH_TS + 999999, "end": EPOCH_TS + 1000000}).json()
        self.assertEqual(doc["pings"], [])
        self.assertTrue(doc["done"])

    def test_reversed_window_is_rejected(self) -> None:
        r = self.get({"start": 200, "end": 100})
        self.assertEqual(r.status_code, 400)
        self.assertIn("start", r.json()["error"])

    def test_bad_start_timestamp_is_rejected(self) -> None:
        r = self.get({"start": "abc"})
        self.assertEqual(r.status_code, 400)

    def test_negative_timestamp_is_rejected(self) -> None:
        r = self.get({"end": -1})
        self.assertEqual(r.status_code, 400)

    def test_out_of_bounds_timestamp_is_rejected(self) -> None:
        r = self.get({"start": 10000000001})
        self.assertEqual(r.status_code, 400)
