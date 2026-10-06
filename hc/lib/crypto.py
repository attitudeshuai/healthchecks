"""Algorithm-agnostic symmetric encryption primitives for channel credentials.

Encrypted values are stored as self-describing text envelopes:

    enc$<version>$<algorithm>$<key id>$<base64 payload>

The envelope records which algorithm and which key was used, so records
encrypted with old keys remain readable during key rotation, and new
algorithms can be introduced without breaking existing records.
"""

from __future__ import annotations

import base64
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_PREFIX = "enc$"
ENVELOPE_VERSION = "1"

# Algorithm identifiers mapped to required key length in bytes.
A256GCM = "A256GCM"
KEY_LENGTHS = {A256GCM: 32}

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class CredentialError(Exception):
    """Raised when an encrypted credential cannot be decrypted."""


class InvalidKey(ValueError):
    """Raised when a key id, algorithm or key material is invalid."""


@dataclass(frozen=True)
class Key:
    id: str
    alg: str
    material: bytes


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    """Decode standard or URL-safe base64, with or without padding."""

    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        # Also accept standard base64 (with "+" and "/" characters).
        try:
            padded = value + "=" * (-len(value) % 4)
            return base64.b64decode(padded, validate=True)
        except Exception:
            raise InvalidKey("Key material is not valid base64.")


def make_key(key_id: str, alg: str, encoded_material: str) -> Key:
    """Build and validate a Key. Algorithm-independent entry point."""

    if not key_id or not _KEY_ID_RE.match(key_id):
        raise InvalidKey(
            f"Invalid key id {key_id!r}: use 1-64 letters, digits, dots, "
            "dashes or underscores."
        )

    if alg not in KEY_LENGTHS:
        supported = ", ".join(sorted(KEY_LENGTHS))
        raise InvalidKey(f"Unsupported encryption algorithm {alg!r} (supported: {supported}).")

    material = _b64decode(encoded_material)
    expected = KEY_LENGTHS[alg]
    if len(material) != expected:
        bits = expected * 8
        raise InvalidKey(
            f"Key {key_id!r} for algorithm {alg} must be {expected} bytes "
            f"({bits} bits), got {len(material)} bytes."
        )

    return Key(id=key_id, alg=alg, material=material)


def is_envelope(value: object) -> bool:
    """Return True if the value looks like an encrypted envelope."""

    if not isinstance(value, str) or not value.startswith(ENVELOPE_PREFIX):
        return False
    parts = value.split("$")
    return len(parts) == 5 and parts[1] == ENVELOPE_VERSION


@dataclass(frozen=True)
class Envelope:
    alg: str
    key_id: str
    payload: bytes


def parse_envelope(value: str) -> Envelope:
    if not is_envelope(value):
        raise CredentialError("Value is not an encrypted envelope.")

    _, _version, alg, key_id, encoded = value.split("$")
    try:
        payload = _b64decode(encoded)
    except InvalidKey:
        raise CredentialError("Encrypted payload is not valid base64.")

    return Envelope(alg=alg, key_id=key_id, payload=payload)


def envelope_prefix(key: Key) -> str:
    """Return the envelope prefix used by records encrypted with the key."""

    return f"{ENVELOPE_PREFIX}{ENVELOPE_VERSION}${key.alg}${key.id}$"


def encrypt(plaintext: str, key: Key) -> str:
    """Encrypt a string and return a self-describing envelope."""

    if key.alg == A256GCM:
        nonce = os.urandom(12)
        ciphertext = AESGCM(key.material).encrypt(
            nonce, plaintext.encode("utf-8"), None
        )
        payload = nonce + ciphertext
    else:  # pragma: no cover
        raise InvalidKey(f"Unsupported encryption algorithm {key.alg!r}.")

    return envelope_prefix(key) + _b64encode(payload)


def decrypt(value: str, keys: Sequence[Key]) -> tuple[str, Key]:
    """Decrypt an envelope, trying the supplied keys in order.

    Matching is done by key id and algorithm recorded in the envelope.
    Raises CredentialError when none of the keys can decrypt the record.
    """

    envelope = parse_envelope(value)
    candidates = [
        key
        for key in keys
        if key.id == envelope.key_id and key.alg == envelope.alg
    ]
    if not candidates:
        raise CredentialError(
            f"No usable decryption key for key id {envelope.key_id!r} "
            f"(algorithm {envelope.alg})."
        )

    for key in candidates:
        try:
            if key.alg == A256GCM:
                nonce, ciphertext = envelope.payload[:12], envelope.payload[12:]
                plaintext = AESGCM(key.material).decrypt(
                    nonce, ciphertext, None
                )
            else:  # pragma: no cover
                continue
        except InvalidTag:
            continue

        return plaintext.decode("utf-8"), key

    raise CredentialError(
        f"Failed to decrypt the record, the key id {envelope.key_id!r} "
        "does not match the record."
    )
