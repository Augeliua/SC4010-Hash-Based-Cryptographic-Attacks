"""Small smoke tests for Milestone 3; no statistical claims from these tests."""
import random
import unittest
from experiments.lamport_experiments import trial


class TestLamportExperiments(unittest.TestCase):
    def test_trial_values(self):
        row = trial(hash_bytes=2, observed_count=5, rng=random.Random(123))
        self.assertGreaterEqual(row['exposed_secrets'], 16)
        self.assertLessEqual(row['exposed_secrets'], 32)
        self.assertIn(row['fixed_target_success'], (0, 1))
        self.assertIn(row['existential_success'], (0, 1))
        self.assertLessEqual(row['search_attempts'], 500)

    def test_same_seed_has_same_attack_outcomes(self):
        a = trial(2, 4, random.Random(4010))
        b = trial(2, 4, random.Random(4010))
        for field in ('exposed_secrets', 'fixed_target_success',
                      'existential_success', 'search_attempts'):
            self.assertEqual(a[field], b[field])


if __name__ == '__main__':
    unittest.main()
