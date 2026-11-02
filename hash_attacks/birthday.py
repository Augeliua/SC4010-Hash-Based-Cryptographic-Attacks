"""Birthday attack: find two different messages with the same truncated hash.

Idea: keep hashing new messages and remember every fingerprint in a
dictionary. The moment a fingerprint repeats, the two messages that produced
it collide. By the birthday paradox this takes about 1.25 * 2^(n/2) hashes,
far fewer than the 2^n you might expect.

Downside: we must STORE every fingerprint, so memory also grows like 2^(n/2).
Pollard's rho (pollards_rho.py) fixes that.
"""
import os
from dataclasses import dataclass

from hash_attacks.common import truncated_sha256


@dataclass
class BirthdayResult:
    message_a: bytes
    message_b: bytes
    digest: bytes
    hashes_computed: int   # how many messages we hashed in total
    table_size: int        # how many fingerprints we had to store (memory cost)


def birthday_attack(n_bytes: int) -> BirthdayResult:
    # A random 8-byte prefix makes every run (trial) independent. After it we
    # append a counter, so every message in one run is guaranteed different:
    # any repeated fingerprint is therefore a genuine collision.
    prefix = os.urandom(8)
    seen = {}  # fingerprint -> the message that produced it
    counter = 0
    while True:
        counter += 1
        message = prefix + counter.to_bytes(8, "big")
        digest = truncated_sha256(message, n_bytes)

        # Have we seen this fingerprint before? If yes, we found a collision.
        earlier = seen.get(digest)
        if earlier is not None:
            return BirthdayResult(earlier, message, digest, counter, len(seen))
        seen[digest] = message
