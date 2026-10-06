from __future__ import annotations

import base64

from django.test import SimpleTestCase

from hc.lib import crypto


def b64key(seed: bytes) -> str:
    return base64.urlsafe_b64encode(seed).decode()


class CryptoTestCase(SimpleTestCase):
    def setUp(self) -> None:
        self.key = crypto.make_key("k1", crypto.A256GCM, b64key(b"a" * 32))

    def test_roundtrip(self) -> None:
        envelope = crypto.encrypt("plain token", self.key)
        self.assertTrue(crypto.is_envelope(envelope))
        plaintext, used = crypto.decrypt(envelope, [self.key])
        self.assertEqual(plaintext, "plain token")
        self.assertEqual(used, self.key)

    def test_envelope_does_not_leak_plaintext(self) -> None:
        envelope = crypto.encrypt("super-secret-token", self.key)
        self.assertNotIn("super-secret-token", envelope)
        self.assertTrue(envelope.startswith("enc$1$A256GCM$k1$"))

    def test_uses_random_nonce(self) -> None:
        self.assertNotEqual(
            crypto.encrypt("same", self.key), crypto.encrypt("same", self.key)
        )

    def test_wrong_key_fails(self) -> None:
        other = crypto.make_key("k2", crypto.A256GCM, b64key(b"b" * 32))
        envelope = crypto.encrypt("plain token", self.key)
        with self.assertRaises(crypto.CredentialError):
            crypto.decrypt(envelope, [other])

    def test_missing_key_id_fails(self) -> None:
        other = crypto.make_key("k2", crypto.A256GCM, b64key(b"b" * 32))
        envelope = crypto.encrypt("plain token", self.key)
        with self.assertRaises(crypto.CredentialError):
            crypto.decrypt(envelope, [other])

    def test_tampered_payload_fails(self) -> None:
        envelope = crypto.encrypt("plain token", self.key)
        tampered = envelope[:-2] + ("AA" if envelope[-2:] != "AA" else "BB")
        with self.assertRaises(crypto.CredentialError):
            crypto.decrypt(tampered, [self.key])

    def test_make_key_rejects_bad_length(self) -> None:
        with self.assertRaises(crypto.InvalidKey):
            crypto.make_key("k1", crypto.A256GCM, b64key(b"short"))

    def test_make_key_rejects_bad_id(self) -> None:
        with self.assertRaises(crypto.InvalidKey):
            crypto.make_key("bad id!", crypto.A256GCM, b64key(b"a" * 32))

    def test_make_key_rejects_unknown_algorithm(self) -> None:
        with self.assertRaises(crypto.InvalidKey):
            crypto.make_key("k1", "RSA", b64key(b"a" * 32))

    def test_is_envelope(self) -> None:
        self.assertFalse(crypto.is_envelope("plain value"))
        self.assertFalse(crypto.is_envelope(""))
        self.assertFalse(crypto.is_envelope(None))
        self.assertFalse(crypto.is_envelope("enc$1$A256GCM$k1"))
        self.assertTrue(
            crypto.is_envelope(
                crypto.encrypt("x", self.key),
            )
        )

    def test_accepts_standard_base64_key(self) -> None:
        standard = base64.b64encode(b"c" * 32).decode()
        key = crypto.make_key("k3", crypto.A256GCM, standard)
        envelope = crypto.encrypt("hello", key)
        plaintext, used = crypto.decrypt(envelope, [key])
        self.assertEqual(plaintext, "hello")
