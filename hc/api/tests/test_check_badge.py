from __future__ import annotations

import time
from datetime import timedelta as td

from django.test.utils import override_settings
from django.utils.http import http_date
from django.utils.timezone import now

from hc.api.models import Check
from hc.test import BaseTestCase


class CheckBadgeTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.check = Check.objects.create(project=self.project, name="foobar")

        self.svg_url = f"/b/2/{self.check.badge_key}.svg"
        self.json_url = f"/b/2/{self.check.badge_key}.json"
        self.with_late_url = f"/b/3/{self.check.badge_key}.json"
        self.shields_url = f"/b/2/{self.check.badge_key}.shields"

    def test_it_handles_bad_badge_key(self) -> None:
        r = self.client.get("/b/2/869fe06a-a604-4140-b15a-118637c25f3e.svg")
        self.assertEqual(r.status_code, 404)

    def test_hidden_check_returns_not_found(self) -> None:
        self.check.public = False
        self.check.save()

        for url in (self.svg_url, self.json_url, self.shields_url):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 404, url)

    def test_it_returns_svg(self) -> None:
        r = self.client.get(self.svg_url)
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")
        self.assertIn("no-cache", r["Cache-Control"])
        self.assertContains(r, "#4c1")

    def test_it_rejects_bad_format(self) -> None:
        r = self.client.get(self.json_url + "foo")
        self.assertEqual(r.status_code, 404)

    def test_it_handles_options(self) -> None:
        r = self.client.options(self.svg_url)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")

    def test_it_handles_new(self) -> None:
        doc = self.client.get(self.json_url).json()
        self.assertEqual(doc, {"status": "up", "total": 1, "grace": 0, "down": 0})

    def test_it_ignores_started_when_down(self) -> None:
        self.check.last_start = now()
        self.check.status = "down"
        self.check.save()

        doc = self.client.get(self.json_url).json()
        self.assertEqual(doc, {"status": "down", "total": 1, "grace": 0, "down": 1})

    def test_it_treats_late_as_up(self) -> None:
        self.check.last_ping = now() - td(days=1, minutes=10)
        self.check.status = "up"
        self.check.save()

        doc = self.client.get(self.json_url).json()
        self.assertEqual(doc, {"status": "up", "total": 1, "grace": 1, "down": 0})

    def test_late_mode_returns_late_status(self) -> None:
        self.check.last_ping = now() - td(days=1, minutes=10)
        self.check.status = "up"
        self.check.save()

        doc = self.client.get(self.with_late_url).json()
        self.assertEqual(doc, {"status": "late", "total": 1, "grace": 1, "down": 0})

    def test_late_mode_ignores_started_when_late(self) -> None:
        self.check.last_start = now()
        self.check.last_ping = now() - td(days=1, minutes=10)
        self.check.status = "up"
        self.check.save()

        doc = self.client.get(self.with_late_url).json()
        self.assertEqual(doc, {"status": "late", "total": 1, "grace": 1, "down": 0})

    def test_it_returns_shields_json(self) -> None:
        doc = self.client.get(self.shields_url).json()
        self.assertEqual(
            doc,
            {
                "schemaVersion": 1,
                "label": "foobar",
                "message": "up",
                "color": "success",
            },
        )


@override_settings(BADGE_CACHE_TIMEOUT=60)
class ConditionalCheckBadgeTestCase(CheckBadgeTestCase):
    # Caching-enabled mode uses max-age instead of the default no-cache.
    def test_it_returns_svg(self) -> None:
        r = self.client.get(self.svg_url)
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")
        self.assertEqual(r["Cache-Control"], "max-age=60")
        self.assertContains(r, "#4c1")

    def test_first_response_carries_validators(self) -> None:
        r = self.client.get(self.json_url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "max-age=60")
        self.assertTrue(r["ETag"])
        self.assertTrue(r["Last-Modified"])
        self.assertTrue(r.content)

    def test_matching_etag_returns_304(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.content, b"")
        self.assertEqual(r["ETag"], etag)

    def test_non_matching_etag_returns_full_content(self) -> None:
        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH='"stale"')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content)
        self.assertNotEqual(r["ETag"], '"stale"')

    def test_fresh_if_modified_since_returns_304(self) -> None:
        last_modified = self.client.get(self.json_url)["Last-Modified"]

        r = self.client.get(self.json_url, HTTP_IF_MODIFIED_SINCE=last_modified)
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.content, b"")

    def test_stale_if_modified_since_returns_full_content(self) -> None:
        old = http_date(time.time() - 3600)
        r = self.client.get(self.json_url, HTTP_IF_MODIFIED_SINCE=old)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content)

    def test_malformed_condition_headers_return_full_content(self) -> None:
        r = self.client.get(self.json_url, HTTP_IF_MODIFIED_SINCE="garbage")
        self.assertEqual(r.status_code, 200)

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH="garbage")
        self.assertEqual(r.status_code, 200)

    def test_etag_changes_when_status_flips(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        self.check.status = "down"
        self.check.save()

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["status"], "down")

    def test_etag_changes_when_renamed(self) -> None:
        etag = self.client.get(self.shields_url)["ETag"]

        self.check.name = "Renamed"
        self.check.save()

        r = self.client.get(self.shields_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["label"], "Renamed")

    def test_hidden_check_returns_not_found_with_conditions(self) -> None:
        self.check.public = False
        self.check.save()

        etag = '"anything"'
        r = self.client.get(
            self.json_url,
            HTTP_IF_NONE_MATCH=etag,
            HTTP_IF_MODIFIED_SINCE=http_date(time.time()),
        )
        self.assertEqual(r.status_code, 404)

    def test_bad_badge_key_still_returns_404(self) -> None:
        r = self.client.get("/b/2/869fe06a-a604-4140-b15a-118637c25f3e.svg")
        self.assertEqual(r.status_code, 404)

    def test_bad_format_still_returns_404(self) -> None:
        r = self.client.get(self.json_url + "foo")
        self.assertEqual(r.status_code, 404)
