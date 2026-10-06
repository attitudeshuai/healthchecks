from __future__ import annotations

import time
from datetime import timedelta as td

from django.conf import settings
from django.core.signing import base64_hmac
from django.test.utils import override_settings
from django.utils.http import http_date
from django.utils.timezone import now

from hc.api.models import Check
from hc.test import BaseTestCase


class BadgeTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.check = Check.objects.create(project=self.project, tags="foo bar")

        sig = base64_hmac(
            str(self.project.badge_key), "foo", settings.SECRET_KEY, algorithm="sha1"
        )
        sig = sig[:8]

        self.svg_url = f"/badge/{self.project.badge_key}/{sig}-2/foo.svg"
        self.json_url = f"/badge/{self.project.badge_key}/{sig}-2/foo.json"
        self.with_late_url = f"/badge/{self.project.badge_key}/{sig}/foo.json"
        self.shields_url = f"/badge/{self.project.badge_key}/{sig}-2/foo.shields"

    def test_it_rejects_bad_signature(self) -> None:
        r = self.client.get(f"/badge/{self.project.badge_key}/12345678/foo.svg")
        self.assertEqual(r.status_code, 404)

    def test_it_returns_svg(self) -> None:
        r = self.client.get(self.svg_url)
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")
        self.assertIn("no-cache", r["Cache-Control"])
        self.assertContains(r, "#4c1")

    def test_it_does_not_send_cache_validators_by_default(self) -> None:
        r = self.client.get(self.json_url)
        self.assertNotIn("ETag", r)
        self.assertNotIn("Last-Modified", r)

    def test_it_excludes_hidden_checks(self) -> None:
        self.check.public = False
        self.check.save()

        doc = self.client.get(self.json_url).json()
        self.assertEqual(doc, {"status": "up", "total": 0, "grace": 0, "down": 0})

    def test_hidden_master_badge_matches_empty_set(self) -> None:
        sig = base64_hmac(
            str(self.project.badge_key), "*", settings.SECRET_KEY, algorithm="sha1"
        )
        url = f"/badge/{self.project.badge_key}/{sig[:8]}-2.svg"

        self.check.public = False
        self.check.save()

        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
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

    def test_it_handles_special_characters(self) -> None:
        self.check.tags = "db@dc1"
        self.check.save()

        sig = base64_hmac(
            str(self.project.badge_key), "db@dc1", settings.SECRET_KEY, algorithm="sha1"
        )
        sig = sig[:8]
        url = f"/badge/{self.project.badge_key}/{sig}/db%2540dc1.svg"

        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)

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
            {"schemaVersion": 1, "label": "foo", "message": "up", "color": "success"},
        )


@override_settings(BADGE_CACHE_TIMEOUT=60)
class ConditionalBadgeTestCase(BadgeTestCase):
    # Override the default-mode header checks inherited from BadgeTestCase:
    # with caching enabled the SVG response carries max-age instead of
    # no-cache, and does carry ETag / Last-Modified validators.
    def test_it_returns_svg(self) -> None:
        r = self.client.get(self.svg_url)
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")
        self.assertEqual(r["Cache-Control"], "max-age=60")
        self.assertContains(r, "#4c1")

    def test_it_does_not_send_cache_validators_by_default(self) -> None:
        r = self.client.get(self.json_url)
        self.assertTrue(r["ETag"])
        self.assertTrue(r["Last-Modified"])

    def test_first_response_carries_validators(self) -> None:
        r = self.client.get(self.json_url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Cache-Control"], "max-age=60")
        self.assertNotIn("no-cache", r["Cache-Control"])
        self.assertTrue(r["ETag"].startswith('"'))
        self.assertTrue(r["ETag"].endswith('"'))
        self.assertTrue(r["Last-Modified"])
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")
        self.assertTrue(r.content)

    def test_matching_etag_returns_304(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.content, b"")
        self.assertEqual(r["ETag"], etag)
        self.assertEqual(r["Cache-Control"], "max-age=60")
        self.assertEqual(r["Access-Control-Allow-Origin"], "*")

    def test_non_matching_etag_returns_full_content(self) -> None:
        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH='"stale"')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content)
        self.assertNotEqual(r["ETag"], '"stale"')

    def test_wildcard_etag_returns_304(self) -> None:
        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH="*")
        self.assertEqual(r.status_code, 304)

    def test_weak_etag_returns_304(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]
        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=f"W/{etag}")
        self.assertEqual(r.status_code, 304)

    def test_multiple_etags_match(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]
        r = self.client.get(
            self.json_url, HTTP_IF_NONE_MATCH=f'"other", {etag}'
        )
        self.assertEqual(r.status_code, 304)

    def test_fresh_if_modified_since_returns_304(self) -> None:
        last_modified = self.client.get(self.json_url)["Last-Modified"]

        r = self.client.get(self.json_url, HTTP_IF_MODIFIED_SINCE=last_modified)
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.content, b"")
        self.assertEqual(r["Cache-Control"], "max-age=60")

    def test_stale_if_modified_since_returns_full_content(self) -> None:
        old = http_date(time.time() - 3600)
        r = self.client.get(self.json_url, HTTP_IF_MODIFIED_SINCE=old)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content)
        self.assertTrue(r["ETag"])

    def test_malformed_if_modified_since_returns_full_content(self) -> None:
        r = self.client.get(self.json_url, HTTP_IF_MODIFIED_SINCE="garbage")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content)

    def test_malformed_if_none_match_returns_full_content(self) -> None:
        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH="garbage")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content)

    def test_if_none_match_takes_precedence_over_ims(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        # Matching validator wins even with a stale IMS
        r = self.client.get(
            self.json_url,
            HTTP_IF_NONE_MATCH=etag,
            HTTP_IF_MODIFIED_SINCE=http_date(time.time() - 3600),
        )
        self.assertEqual(r.status_code, 304)

        # Non-matching validator loses even with a fresh IMS
        last_modified = self.client.get(self.json_url)["Last-Modified"]
        r = self.client.get(
            self.json_url,
            HTTP_IF_NONE_MATCH='"other"',
            HTTP_IF_MODIFIED_SINCE=last_modified,
        )
        self.assertEqual(r.status_code, 200)

    def test_svg_304_has_empty_body(self) -> None:
        etag = self.client.get(self.svg_url)["ETag"]
        r = self.client.get(self.svg_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 304)
        self.assertEqual(r.content, b"")

    def test_etag_changes_when_status_flips(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        self.check.status = "down"
        self.check.save()

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["status"], "down")

    def test_etag_changes_when_check_set_changes(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        Check.objects.create(project=self.project, tags="foo")

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["total"], 2)

    def test_etag_changes_when_visibility_flips(self) -> None:
        etag = self.client.get(self.json_url)["ETag"]

        self.check.public = False
        self.check.save()

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["total"], 0)

    def test_etag_changes_when_tags_change(self) -> None:
        other = Check.objects.create(project=self.project, tags="bar")

        # An unrelated check must not change the tag badge's validator
        r = self.client.get(self.json_url)
        etag = r["ETag"]
        self.assertEqual(r.json()["total"], 1)

        # Tagging the other check with "foo" pulls it into the badge
        other.tags = "bar foo"
        other.save()

        r = self.client.get(self.json_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["total"], 2)

    def test_etag_differs_by_aggregation_mode(self) -> None:
        two_state = self.client.get(self.json_url)["ETag"]
        three_state = self.client.get(self.with_late_url)["ETag"]
        self.assertNotEqual(two_state, three_state)

    def test_all_checks_hidden_returns_empty_set(self) -> None:
        self.check.public = False
        self.check.save()

        doc = self.client.get(self.json_url).json()
        self.assertEqual(doc, {"status": "up", "total": 0, "grace": 0, "down": 0})

        r = self.client.get(self.svg_url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "#4c1")

        doc = self.client.get(self.shields_url).json()
        self.assertEqual(doc["message"], "up")

    def test_bad_signature_still_returns_404(self) -> None:
        r = self.client.get(f"/badge/{self.project.badge_key}/12345678/foo.svg")
        self.assertEqual(r.status_code, 404)

    def test_bad_format_still_returns_404(self) -> None:
        r = self.client.get(self.json_url + "foo")
        self.assertEqual(r.status_code, 404)
