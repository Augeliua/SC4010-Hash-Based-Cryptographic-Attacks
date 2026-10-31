"""Run with: python -m unittest discover -s tests -v"""
import unittest
from signatures.wots_plus import (
    base16_digits, checksum_digits, chain, generate_keypair, lengths,
    sign, signing_digits, verify,
)


class TestWOTSPlus(unittest.TestCase):
    def test_lengths_and_checksum(self):
        self.assertEqual(lengths(32), (64, 3))
        self.assertEqual(lengths(2), (4, 2))
        self.assertEqual(checksum_digits((15, 0, 5, 10), 2), (1, 14))

    def test_sign_and_verify_full(self):
        private, public = generate_keypair(32)
        sig = sign(b'Pay Bob $10', private)
        self.assertEqual(len(sig), 67)
        self.assertTrue(verify(b'Pay Bob $10', sig, public))
        self.assertFalse(verify(b'Pay Bob $100', sig, public))
        self.assertFalse(verify(b'Pay Bob $10', sig[:-1], public))

    def test_sign_and_verify_toy(self):
        private, public = generate_keypair(2)
        sig = sign(b'toy', private)
        self.assertEqual(len(sig), 6)
        self.assertTrue(verify(b'toy', sig, public))
        self.assertFalse(verify(b'changed', sig, public))

    def test_chain_composition(self):
        private, public = generate_keypair(2)
        start = private.starts[0]
        halfway = chain(start, 0, 6, 0, private.public_seed, 2)
        end = chain(halfway, 6, 9, 0, private.public_seed, 2)
        self.assertEqual(end, public.ends[0])


if __name__ == '__main__':
    unittest.main()
