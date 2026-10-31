"""Run: python -m unittest discover -s tests -v"""
import unittest
from dataclasses import replace
from signatures.xmss import XMSSSigner, verify
from attacks.xmss_rollback import perform_rollback_attack


class XMSSTests(unittest.TestCase):
    def test_normal_signing_and_auth_path(self):
        signer = XMSSSigner(height=2, n=2)
        a, b = signer.sign(b'A'), signer.sign(b'B')
        self.assertEqual((a.index, b.index), (0, 1))
        self.assertTrue(verify(b'A', a, signer.public))
        self.assertTrue(verify(b'B', b, signer.public))
        self.assertFalse(verify(b'wrong', a, signer.public))
        self.assertFalse(verify(b'A', replace(a, index=1), signer.public))
        self.assertFalse(verify(b'A', replace(a, auth_path=(bytes(32),)*2), signer.public))
        signer.sign(b'C'); signer.sign(b'D')
        with self.assertRaises(RuntimeError):
            signer.sign(b'E')

    def test_rollback_creates_real_forgery(self):
        signer = XMSSSigner(height=4, n=2)
        result = perform_rollback_attack(signer, observations=12)
        self.assertEqual(result.reused_index, 0)
        self.assertTrue(verify(result.forged_message, result.forged, signer.public))
        self.assertEqual(len(result.forged.auth_path), 4)


if __name__ == '__main__':
    unittest.main()
