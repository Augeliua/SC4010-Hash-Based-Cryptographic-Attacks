"""Shared helpers for the hash-collision half of the project.

Every attack in hash_attacks/ uses the SAME toy hash as signatures/lamport.py:
the first n_bytes of SHA-256. Using an identical function matters, because a
collision we find here must also be a collision for her sign()/verify().
tests/test_hash_attacks.py checks that the two functions always agree.

We truncate in whole bytes (8, 16, 24, ... bits) because her sha256_truncated
works in bytes. Educational code, not production cryptography.
"""
from functools import partial
from hashlib import sha256
from math import pi, sqrt

from signatures.lamport import sha256_truncated


def truncated_sha256(data: bytes, n_bytes: int) -> bytes:
    """First n_bytes of SHA-256(data). Same output as her sha256_truncated.

    We call hashlib directly instead of her function only for speed: our
    attacks call this tens of millions of times, so skipping her input
    checks gives a noticeable speedup. The test suite proves they match.
    """
    return sha256(data).digest()[:n_bytes]


def lamport_hash(n_bytes: int):
    """Return the exact hash_fn to pass into her generate_keypair/sign/verify.

    This IS her function (not a copy), so the signature side of every demo
    runs on her code, unchanged.
    """
    return partial(sha256_truncated, digest_bytes=n_bytes)


def expected_collision_work(n_bits: int) -> float:
    """Birthday bound: expected hashes before the FIRST collision.

    With N = 2^n possible fingerprints, after k random hashes there are about
    k^2 / 2 pairs, each matching with probability 1/N. Collisions become
    likely once k^2 / (2N) is around 1, so k is around sqrt(N) = 2^(n/2).
    The exact expected value is sqrt(pi/2 * N), about 1.25 * 2^(n/2).
    """
    return sqrt(pi / 2 * 2 ** n_bits)
