"""Regression tests: every claimed forgery must pass its verifier."""
import unittest
from signatures.wots_plus import generate_keypair, sign, verify
from attacks.wots_attacks import (sign_without_checksum, verify_without_checksum,
    search_checksum_removal, extend_signature, search_key_reuse)


class WOTSAttackTests(unittest.TestCase):
    def test_checksum_removal_forgery_and_protected_barrier(self):
        priv, pub = generate_keypair(n=2)
        original = b'Original approval'
        weak = sign_without_checksum(original, priv)
        result = search_checksum_removal(original, weak, pub, max_attempts=100_000)
        self.assertIsNotNone(result)
        self.assertNotEqual(result.message, original)
        self.assertTrue(verify_without_checksum(result.message, result.signature, pub))
        # For the SAME two messages, restoring checksum makes simple extension impossible.
        protected = sign(original, priv)
        self.assertIsNone(extend_signature(original, protected, result.message,
                                           pub, include_checksum=True))

    def test_key_reuse_forges_even_with_checksum(self):
        priv, pub = generate_keypair(n=2)
        messages = [f'Signed #{i}'.encode() for i in range(12)]
        observations = [(msg, sign(msg, priv)) for msg in messages]
        forged = search_key_reuse(observations, pub, max_attempts=100_000)
        self.assertIsNotNone(forged)
        self.assertNotIn(forged.message, messages)
        self.assertTrue(verify(forged.message, forged.signature, pub))


if __name__ == '__main__':
    unittest.main()
