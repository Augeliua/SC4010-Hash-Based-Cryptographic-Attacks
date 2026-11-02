"""Tests for hash_attacks/. Run from the repo root: python -m unittest -v

Each test checks a claim we make in the presentation, using HER Lamport code
for every signing and verification step.
"""
import os
import unittest
from hashlib import sha256

from hash_attacks.birthday import birthday_attack
from hash_attacks.common import lamport_hash, truncated_sha256
from hash_attacks.length_extension import NaiveServer, attack_unknown_key_length, sha256_resume
from hash_attacks.meaningful_collision import AMOUNTS, contract_amount, find_meaningful_collision
from hash_attacks.multi_target import crack_public_key, forged_private_key
from hash_attacks.pollards_rho import StepFunction, find_collision, floyd_rho
from signatures.lamport import generate_keypair, sha256_truncated, sign, verify


class TestHashAttacks(unittest.TestCase):
    def assertCollision(self, a, b, n_bytes):
        self.assertNotEqual(a, b)
        self.assertEqual(sha256_truncated(a, n_bytes), sha256_truncated(b, n_bytes))

    def test_our_hash_matches_lamport_hash(self):
        # If these ever differ, our collisions would not break her signatures.
        for n_bytes in range(1, 33):
            data = os.urandom(n_bytes * 3)
            self.assertEqual(truncated_sha256(data, n_bytes), sha256_truncated(data, n_bytes))

    def test_birthday(self):
        r = birthday_attack(3)
        self.assertCollision(r.message_a, r.message_b, 3)

    def test_floyd_rho(self):
        r = floyd_rho(StepFunction(3))
        self.assertCollision(r.message_a, r.message_b, 3)

    def test_distinguished_point_rho(self):
        r = find_collision(4, workers=1)
        self.assertCollision(r.message_a, r.message_b, 4)

    def test_meaningful_collision_forges_lamport_signature(self):
        n_bytes = 3
        cheap, expensive, _, _ = find_meaningful_collision(n_bytes, workers=1)
        self.assertEqual(contract_amount(cheap), AMOUNTS[0])
        self.assertEqual(contract_amount(expensive), AMOUNTS[1])
        h = lamport_hash(n_bytes)
        private, public = generate_keypair(h)
        signature = sign(cheap, private, h)              # Alice signs $10
        self.assertTrue(verify(expensive, signature, public, h))  # valid for $10,000
        # With full SHA-256 the two contracts no longer collide.
        self.assertNotEqual(sha256(cheap).digest(), sha256(expensive).digest())

    def test_multi_target_recovers_whole_key(self):
        h = lamport_hash(2)
        _, public = generate_keypair(h)
        result = crack_public_key(public, 2)
        self.assertEqual(len(result.recovered), result.total_targets)
        key = forged_private_key(result, len(public.hashes))
        message = b"Alice never signed this"
        self.assertTrue(verify(message, sign(message, key, h), public, h))

    def test_our_sha256_matches_hashlib(self):
        for length in (0, 1, 55, 56, 63, 64, 65, 300):
            data = os.urandom(length)
            self.assertEqual(sha256_resume(data), sha256(data).digest())

    def test_length_extension(self):
        server = NaiveServer(os.urandom(20))
        message = b"user=alice&role=student"
        found = attack_unknown_key_length(server, message, server.tag(message), b"&role=admin")
        self.assertIsNotNone(found)
        key_length, forged_message, forged_tag = found
        self.assertEqual(key_length, 20)
        self.assertTrue(forged_message.endswith(b"&role=admin"))
        self.assertTrue(server.accepts(forged_message, forged_tag))


if __name__ == "__main__":
    unittest.main()
