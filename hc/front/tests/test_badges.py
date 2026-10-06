from __future__ import annotations

from django.core.signing import base64_hmac
from django.conf import settings
from django.test.utils import override_settings

from hc.api.models import Check
from hc.test import BaseTestCase


@override_settings(SITE_ROOT="https://example.org")
class BadgesTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.project.badge_key = "alices-badge-key"
        self.project.save()

        self.check = Check.objects.create(project=self.project, tags="foo a-B_1  baz@")

        self.url = f"/projects/{self.project.code}/badges/"

    def test_it_shows_form(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.get(self.url)
        self.assertContains(r, "foo")
        self.assertContains(r, "a-B_1")
        self.assertContains(r, self.project.badge_key)

    def test_it_checks_ownership(self) -> None:
        self.client.login(username="charlie@example.org", password="password")
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 404)

    def test_team_access_works(self) -> None:
        # Logging in as bob, not alice. Bob has team access so this
        # should work.
        self.client.login(username="bob@example.org", password="password")
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)

    @override_settings(MASTER_BADGE_LABEL="Overall Status")
    def test_it_previews_master_svg(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        payload = {"target": "all", "fmt": "svg", "states": "2"}
        r = self.client.post(self.url, payload)

        self.assertContains(r, "![Overall Status]")

    def test_it_previews_tag_svg(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        payload = {"target": "tag", "tag": "foo", "fmt": "svg", "states": "2"}
        r = self.client.post(self.url, payload)

        self.assertContains(r, "https://example.org/badge/alices-badge-key/")
        self.assertContains(r, "foo.svg")
        self.assertContains(r, "![foo]")

    def test_it_previews_check_svg(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        payload = {
            "target": "check",
            "check": self.check.code,
            "fmt": "svg",
            "states": "2",
        }
        r = self.client.post(self.url, payload)
        self.assertContains(r, f"https://example.org/b/2/{self.check.badge_key}.svg")

    def test_it_handles_special_characters_in_tags(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        payload = {"target": "tag", "tag": "db@dc1", "fmt": "svg", "states": "2"}
        r = self.client.post(self.url, payload)
        self.assertContains(r, "db%2540dc1.svg")
        self.assertContains(r, "![db@dc1]")

    def test_it_previews_json(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        payload = {"target": "tag", "tag": "foo", "fmt": "json", "states": "2"}
        r = self.client.post(self.url, payload)

        self.assertContains(r, "fetch-json")
        self.assertContains(r, "foo.json")
        self.assertNotContains(r, "![foo]")

    def test_it_previews_shields(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        payload = {"target": "tag", "tag": "foo", "fmt": "shields", "states": "2"}
        r = self.client.post(self.url, payload)

        self.assertContains(r, "https://img.shields.io/endpoint")
        self.assertContains(r, "%3A%2F%2F")  # url-encoded "://"
        self.assertContains(r, "foo.shields")
        self.assertContains(r, "![foo]")


class BadgeVisibilityTestCase(BadgesTestCase):
    def test_it_shows_visibility_form(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.get(self.url)

        self.assertContains(r, f'action="/projects/{self.project.code}/badges/visibility/"')
        self.assertContains(r, f'value="{self.check.code}"')
        self.check.refresh_from_db()
        self.assertTrue(self.check.public)

    def test_it_hides_check(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.post(
            f"/projects/{self.project.code}/badges/visibility/", {"visible": []}
        )
        self.assertEqual(r.status_code, 302)

        self.check.refresh_from_db()
        self.assertFalse(self.check.public)

    def test_it_shows_check(self) -> None:
        self.check.public = False
        self.check.save()

        self.client.login(username="alice@example.org", password="password")
        r = self.client.post(
            f"/projects/{self.project.code}/badges/visibility/",
            {"visible": [str(self.check.code)]},
        )
        self.assertEqual(r.status_code, 302)

        self.check.refresh_from_db()
        self.assertTrue(self.check.public)

    def test_rw_member_can_update_visibility(self) -> None:
        self.client.login(username="bob@example.org", password="password")
        r = self.client.post(
            f"/projects/{self.project.code}/badges/visibility/",
            {"visible": [str(self.check.code)]},
        )
        self.assertEqual(r.status_code, 302)

    def test_it_checks_ownership(self) -> None:
        self.client.login(username="charlie@example.org", password="password")
        r = self.client.post(
            f"/projects/{self.project.code}/badges/visibility/",
            {"visible": [str(self.check.code)]},
        )
        self.assertEqual(r.status_code, 404)

    def test_it_rejects_requires_post(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.get(f"/projects/{self.project.code}/badges/visibility/")
        self.assertEqual(r.status_code, 405)

    def test_it_rejects_malformed_uuid(self) -> None:
        self.client.login(username="alice@example.org", password="password")
        r = self.client.post(
            f"/projects/{self.project.code}/badges/visibility/",
            {"visible": ["not-a-uuid"]},
        )
        self.assertEqual(r.status_code, 400)

        self.check.refresh_from_db()
        self.assertTrue(self.check.public)

    @override_settings(BADGE_CACHE_TIMEOUT=60)
    def test_visibility_change_immediately_invalidates_badges(self) -> None:
        sig = base64_hmac(
            str(self.project.badge_key), "foo", settings.SECRET_KEY, algorithm="sha1"
        )
        tag_url = f"/badge/{self.project.badge_key}/{sig[:8]}-2/foo.json"
        check_url = f"/b/2/{self.check.badge_key}.json"

        self.client.login(username="alice@example.org", password="password")
        etag = self.client.get(tag_url)["ETag"]

        # Hide the only check via the web form
        self.client.post(
            f"/projects/{self.project.code}/badges/visibility/", {"visible": []}
        )

        # A conditional request with the old validator must get full content
        r = self.client.get(tag_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r["ETag"], etag)
        self.assertEqual(r.json()["total"], 0)

        # The single-check badge now returns 404
        self.assertEqual(self.client.get(check_url).status_code, 404)

        # Show it again: the badge is reachable and negotiates a new validator
        self.client.post(
            f"/projects/{self.project.code}/badges/visibility/",
            {"visible": [str(self.check.code)]},
        )
        r = self.client.get(check_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total"], 1)
