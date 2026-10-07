from __future__ import annotations

from datetime import datetime, timezone

import time_machine
from django.utils.timezone import now

from hc.accounts.models import Profile, Project, QuotaExceeded
from hc.api.models import Check
from hc.test import BaseTestCase

CURRENT_MONTH = datetime(2020, 1, 15, 12, tzinfo=timezone.utc)
NEXT_MONTH = datetime(2020, 2, 1, 0, 1, tzinfo=timezone.utc)


@time_machine.travel(CURRENT_MONTH)
class AtomicQuotaTestCase(BaseTestCase):
    def test_authorize_sms_consumes_quota(self) -> None:
        self.profile.sms_limit = 2
        self.profile.save()

        self.assertTrue(self.profile.authorize_sms())
        self.assertTrue(self.profile.authorize_sms())

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.sms_sent, 2)
        self.assertIsNotNone(self.profile.last_sms_date)

    def test_authorize_sms_rejects_at_limit_without_changing_counter(self) -> None:
        self.profile.sms_limit = 2
        self.profile.sms_sent = 2
        self.profile.last_sms_date = now()
        self.profile.save()

        # The rejected request must not deduct anything, and retrying it must
        # not push the counter negative:
        self.assertFalse(self.profile.authorize_sms())
        self.assertFalse(self.profile.authorize_sms())

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.sms_sent, 2)
        self.assertGreaterEqual(self.profile.sms_sent, 0)

    def test_authorize_sms_resets_counter_in_new_month(self) -> None:
        self.profile.sms_limit = 5
        self.profile.sms_sent = 5
        self.profile.last_sms_date = datetime(2020, 1, 31, tzinfo=timezone.utc)
        self.profile.save()

        with time_machine.travel(NEXT_MONTH):
            self.assertTrue(self.profile.authorize_sms())

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.sms_sent, 1)

    def test_authorize_call_rejects_at_limit_without_changing_counter(self) -> None:
        self.profile.call_limit = 1
        self.profile.calls_sent = 1
        self.profile.last_call_date = now()
        self.profile.save()

        self.assertFalse(self.profile.authorize_call())
        self.assertFalse(self.profile.authorize_call())

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.calls_sent, 1)
        self.assertGreaterEqual(self.profile.calls_sent, 0)

    def test_authorize_call_resets_counter_in_new_month(self) -> None:
        self.profile.call_limit = 5
        self.profile.calls_sent = 5
        self.profile.last_call_date = datetime(2020, 1, 20, tzinfo=timezone.utc)
        self.profile.save()

        with time_machine.travel(NEXT_MONTH):
            self.assertTrue(self.profile.authorize_call())

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.calls_sent, 1)

    def test_reserve_check_slot_allows_create_inside_lock(self) -> None:
        self.profile.check_limit = 1
        self.profile.save()

        with self.profile.reserve_check_slot():
            Check.objects.create(project=self.project)

        self.assertEqual(Check.objects.filter(project__owner=self.alice).count(), 1)

    def test_reserve_check_slot_raises_at_limit(self) -> None:
        self.profile.check_limit = 1
        self.profile.save()
        Check.objects.create(project=self.project)

        with self.assertRaises(QuotaExceeded) as cm:
            with self.profile.reserve_check_slot():
                Check.objects.create(project=self.project)

        # The check created inside the failed block is rolled back, no
        # half-finished records:
        self.assertIn("check quota exhausted", cm.exception.reason)
        self.assertEqual(Check.objects.filter(project__owner=self.alice).count(), 1)

    def test_reserve_check_slot_uses_lowered_limit(self) -> None:
        # Three existing checks, and the admin lowers the limit to two.
        # Existing over-limit checks are kept, but no new one can be created:
        for _ in range(3):
            Check.objects.create(project=self.project)
        self.profile.check_limit = 2
        self.profile.save()

        with self.assertRaises(QuotaExceeded):
            with self.profile.reserve_check_slot():
                Check.objects.create(project=self.project)

        self.assertEqual(Check.objects.filter(project__owner=self.alice).count(), 3)

    def test_reserve_check_slot_covers_all_owned_projects(self) -> None:
        # The quota is account-wide, it counts checks across all projects the
        # profile owner owns.
        second_project = Project(owner=self.alice, badge_key="alice-second")
        second_project.save()

        Check.objects.create(project=self.project)
        self.profile.check_limit = 1
        self.profile.save()

        with self.assertRaises(QuotaExceeded):
            with self.profile.reserve_check_slot():
                Check.objects.create(project=second_project)

    def test_fresh_profile_instance_sees_committed_counter(self) -> None:
        # Simulate a second, concurrent worker reloading the profile after a
        # deduction committed:
        self.profile.sms_limit = 2
        self.profile.save()
        self.assertTrue(self.profile.authorize_sms())

        fresh = Profile.objects.get(pk=self.profile.pk)
        self.assertEqual(fresh.sms_sent_this_month(), 1)
        self.assertTrue(fresh.authorize_sms())
        self.assertFalse(fresh.authorize_sms())
        fresh.refresh_from_db()
        self.assertEqual(fresh.sms_sent, 2)
