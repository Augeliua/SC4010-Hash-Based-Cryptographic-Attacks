import unittest
from hashlib import sha256
from signatures.lamport import generate_keypair, sign, verify, sha256_truncated

class TestLamport(unittest.TestCase):
    def test_valid_and_tampered(self):
        private, public = generate_keypair()
        signature = sign(b"Pay Bob $10", private)
        self.assertTrue(verify(b"Pay Bob $10", signature, public))
        self.assertFalse(verify(b"Pay Bob $100", signature, public))
        self.assertFalse(verify(b"Pay Bob $10", signature[:-1], public))
        self.assertEqual(len(signature), 256)
        self.assertEqual(len(signature) * sha256().digest_size, 8192)

    def test_toy_hash(self):
        toy_hash = lambda data: sha256_truncated(data, 2)
        private, public = generate_keypair(toy_hash)
        signature = sign(b"hello", private, toy_hash)
        self.assertTrue(verify(b"hello", signature, public, toy_hash))
        self.assertEqual(len(signature), 16)

if __name__ == "__main__":
    unittest.main()
