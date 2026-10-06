"""Loading and validation of channel credential encryption settings.

Configuration (environment variables, see hc/settings.py):

* CREDENTIALS_ENCRYPTION     - master switch, default off
* CREDENTIALS_ALGORITHM      - algorithm for the current key, default A256GCM
* CREDENTIALS_KEY_ID         - identifier of the current key
* CREDENTIALS_KEY            - current key material, base64 (or CREDENTIALS_KEY_FILE)
* CREDENTIALS_OLD_KEYS       - JSON list of old keys for rotation, e.g.
                               [{"id": "old", "alg": "A256GCM", "key": "..."}]
* CREDENTIALS_AUDIT_RETENTION_DAYS - how long to keep access audit records
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from hc.lib import crypto


@dataclass
class Keyring:
    enabled: bool
    current: crypto.Key | None
    old_keys: list[crypto.Key] = field(default_factory=list)
    audit_retention_days: int = 365

    @property
    def all_keys(self) -> Sequence[crypto.Key]:
        if self.current is None:
            return self.old_keys
        return [self.current, *self.old_keys]

    def encrypt(self, plaintext: str) -> str:
        if self.current is None:
            raise crypto.CredentialError(
                "Credential encryption is enabled but no current key is configured."
            )
        return crypto.encrypt(plaintext, self.current)

    def decrypt_record(self, value: str) -> tuple[str, crypto.Key | None]:
        """Decrypt a stored value.

        Returns (plaintext, key used). Plain, unencrypted values are returned
        as-is with key=None. The current key is tried first, then old keys.
        """

        if not crypto.is_envelope(value):
            return value, None

        plaintext, key = crypto.decrypt(value, self.all_keys)
        return plaintext, key

    def current_envelope_prefix(self) -> str:
        if self.current is None:
            return ""
        return crypto.envelope_prefix(self.current)

    def is_current(self, value: str) -> bool:
        return bool(value) and value.startswith(self.current_envelope_prefix())


def validate_settings(
    *,
    enabled: bool,
    algorithm: str,
    current_id: str | None,
    current_key: str | None,
    old_keys_raw: str | None,
    retention_days: int | None,
) -> list[tuple[str, str]]:
    """Validate configuration. Returns a list of (message, hint) tuples."""

    errors: list[tuple[str, str]] = []
    if not enabled:
        return errors

    if not current_id:
        errors.append(
            (
                "CREDENTIALS_KEY_ID is not set.",
                "Set CREDENTIALS_KEY_ID to the identifier of the current key.",
            )
        )

    if not current_key:
        errors.append(
            (
                "CREDENTIALS_KEY is not set.",
                "Set CREDENTIALS_KEY (or CREDENTIALS_KEY_FILE) to the current key.",
            )
        )
    elif current_id and algorithm:
        try:
            crypto.make_key(current_id, algorithm, current_key)
        except crypto.InvalidKey as e:
            errors.append((str(e), "Generate a key of the required length."))

    old_entries: list[dict[str, Any]] = []
    if old_keys_raw:
        try:
            parsed = json.loads(old_keys_raw)
            if not isinstance(parsed, list):
                raise ValueError
            old_entries = [e for e in parsed if isinstance(e, dict)]
            if len(old_entries) != len(parsed):
                raise ValueError
        except (ValueError, TypeError):
            errors.append(
                (
                    "CREDENTIALS_OLD_KEYS must be a JSON list of key objects.",
                    'Example: [{"id": "old", "key": "..."}]',
                )
            )

    seen_ids: set[str] = set()
    if current_id:
        seen_ids.add(current_id)

    for entry in old_entries:
        kid = entry.get("id")
        material = entry.get("key")
        alg = entry.get("alg", algorithm)
        if not kid or not material:
            errors.append(
                (
                    "Each entry in CREDENTIALS_OLD_KEYS needs 'id' and 'key'.",
                    'Example: {"id": "old", "key": "..."}',
                )
            )
            continue
        if kid in seen_ids:
            errors.append(
                (
                    f"Duplicate key id {kid!r} in CREDENTIALS_OLD_KEYS.",
                    "Key ids, including the current key id, must be unique.",
                )
            )
            continue
        seen_ids.add(kid)
        try:
            crypto.make_key(str(kid), str(alg), str(material))
        except crypto.InvalidKey as e:
            errors.append((str(e), "Update or remove the old key."))

    if retention_days is None or retention_days <= 0:
        errors.append(
            (
                "CREDENTIALS_AUDIT_RETENTION_DAYS must be a positive integer.",
                "Set CREDENTIALS_AUDIT_RETENTION_DAYS to a positive integer value.",
            )
        )

    return errors


def _parse_old_keys(
    old_keys_raw: str | None, default_alg: str
) -> list[crypto.Key]:
    keys: list[crypto.Key] = []
    if not old_keys_raw:
        return keys

    parsed = json.loads(old_keys_raw)
    for entry in parsed:
        keys.append(
            crypto.make_key(
                str(entry["id"]),
                str(entry.get("alg", default_alg)),
                str(entry["key"]),
            )
        )
    return keys


@lru_cache(maxsize=1)
def get_keyring() -> Keyring:
    enabled = bool(getattr(settings, "CREDENTIALS_ENCRYPTION", False))
    algorithm = str(getattr(settings, "CREDENTIALS_ALGORITHM", crypto.A256GCM))
    current_id = getattr(settings, "CREDENTIALS_KEY_ID", None)
    current_key = getattr(settings, "CREDENTIALS_KEY", None)
    old_keys_raw = getattr(settings, "CREDENTIALS_OLD_KEYS", None)
    retention = getattr(settings, "CREDENTIALS_AUDIT_RETENTION_DAYS", 365)

    if not enabled:
        # Even when encryption is disabled, already-encrypted records should
        # remain readable if the keys are still configured. Never fail startup
        # over optional key configuration when the feature is turned off.
        try:
            current = (
                crypto.make_key(current_id, algorithm, current_key)
                if current_id and current_key
                else None
            )
            olds = _parse_old_keys(old_keys_raw, algorithm) if current else []
        except (crypto.InvalidKey, ValueError, TypeError, KeyError):
            current, olds = None, []
        return Keyring(enabled=False, current=current, old_keys=olds)

    errors = validate_settings(
        enabled=True,
        algorithm=algorithm,
        current_id=current_id,
        current_key=current_key,
        old_keys_raw=old_keys_raw,
        retention_days=retention,
    )
    if errors:
        message = "; ".join(msg for msg, _hint in errors)
        raise ImproperlyConfigured(message)

    assert current_id is not None
    assert current_key is not None
    return Keyring(
        enabled=True,
        current=crypto.make_key(current_id, algorithm, current_key),
        old_keys=_parse_old_keys(old_keys_raw, algorithm),
        audit_retention_days=int(retention),
    )


def reset_keyring() -> None:
    """Drop the cached keyring. Used by tests and key rotation tooling."""

    get_keyring.cache_clear()
