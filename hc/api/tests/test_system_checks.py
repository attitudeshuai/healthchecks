from __future__ import annotations

from django.test.utils import override_settings

from hc.api.apps import api_key_governance_check, settings_check
from hc.test import BaseTestCase


@override_settings(EMAIL_HOST="localhost", APPRISE_ENABLED=False)
class SystemChecksCase(BaseTestCase):
    @override_settings(SITE_ROOT="example.com")
    def test_it_validates_site_root_syntax(self) -> None:
        ids = [item.id for item in settings_check(None, None)]
        self.assertEqual(ids, ["hc.api.W001"])

    @override_settings(SITE_ROOT="http://surprise.example.com")
    def test_it_checks_site_root_host_is_present_in_allowed_hosts(self) -> None:
        ids = [item.id for item in settings_check(None, None)]
        self.assertEqual(ids, ["hc.api.E002"])

    @override_settings(MAILERS={})
    def test_it_warns_about_missing_smtp_credentials(self) -> None:
        ids = [item.id for item in settings_check(None, None)]
        self.assertEqual(ids, ["hc.api.W002"])

    @override_settings(SECURE_PROXY_SSL_HEADER="abc")
    def test_it_checks_secure_proxy_ssl_header_tupleness(self) -> None:
        ids = [item.id for item in settings_check(None, None)]
        self.assertEqual(ids, ["hc.api.W005"])

    @override_settings(APPRISE_ENABLED=True, INTEGRATIONS_ALLOW_PRIVATE_IPS=False)
    def test_it_checks_apprise_and_private_ips(self) -> None:
        ids = [item.id for item in settings_check(None, None)]
        self.assertEqual(ids, ["hc.api.W006"])


class ApiKeyGovernanceChecksCase(BaseTestCase):
    def test_default_configuration_passes(self) -> None:
        self.assertEqual(api_key_governance_check(None, None), [])

    @override_settings(API_KEY_ROTATION_ENABLED=True)
    def test_enabled_with_valid_durations_passes(self) -> None:
        self.assertEqual(api_key_governance_check(None, None), [])

    @override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_PRUNE_SCAN_PERIOD=10)
    def test_it_rejects_scan_period_shorter_than_window(self) -> None:
        ids = [item.id for item in api_key_governance_check(None, None)]
        self.assertEqual(ids, ["hc.api.E006"])

    @override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_ROTATION_WINDOW=0)
    def test_it_rejects_non_positive_window(self) -> None:
        ids = [item.id for item in api_key_governance_check(None, None)]
        self.assertIn("hc.api.E005", ids)
        self.assertNotIn("hc.api.E006", ids)

    @override_settings(API_KEY_EXPIRATION_ENABLED=True)
    def test_it_rejects_expiry_enabled_without_rotation(self) -> None:
        ids = [item.id for item in api_key_governance_check(None, None)]
        self.assertEqual(ids, ["hc.api.E004"])

    @override_settings(
        API_KEY_ROTATION_ENABLED=True,
        API_KEY_EXPIRATION_ENABLED=True,
        API_KEY_LIFETIME=0,
    )
    def test_it_validates_lifetime_when_expiry_enabled(self) -> None:
        ids = [item.id for item in api_key_governance_check(None, None)]
        self.assertIn("hc.api.E005", ids)

    @override_settings(API_KEY_ROTATION_ENABLED=True, API_KEY_AUDIT_RETENTION=None)
    def test_it_rejects_none_duration(self) -> None:
        ids = [item.id for item in api_key_governance_check(None, None)]
        self.assertIn("hc.api.E005", ids)
