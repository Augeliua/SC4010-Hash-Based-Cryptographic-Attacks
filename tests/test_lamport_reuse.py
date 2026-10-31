import unittest
from functools import partial
from signatures.lamport import generate_keypair, sign, verify, sha256_truncated
from attacks.lamport_reuse import collect_exposed, forge_for_message, find_forgery

class TestLamportReuse(unittest.TestCase):
    def test_reuse_forgery(self):
        toy_hash = partial(sha256_truncated, digest_bytes=2)
        private, public = generate_keypair(toy_hash)
        messages = [f"Authorized payment {i}".encode() for i in range(5)]
        exposed = collect_exposed([(m, sign(m, private, toy_hash)) for m in messages], toy_hash)
        result = find_forgery(exposed, toy_hash, messages)
        self.assertIsNotNone(result)
        target, forged_signature, _ = result
        self.assertNotIn(target, messages)
        self.assertTrue(verify(target, forged_signature, public, toy_hash))

    def test_single_signature_cannot_change_digest_bits(self):
        toy_hash = partial(sha256_truncated, digest_bytes=2)
        private, _ = generate_keypair(toy_hash)
        original = b"first"
        exposed = collect_exposed([(original, sign(original, private, toy_hash))], toy_hash)
        # This target has a different digest, so unavailable secrets are needed.
        target = b"second"
        self.assertIsNone(forge_for_message(target, exposed, toy_hash))

if __name__ == "__main__":
    unittest.main()
