#rmbing every fingerprint in dict

import os
from dataclasses import dataclass

from hash_attacks.common import truncated_sha256


@dataclass
class BirthdayResult:
    message_a: bytes
    message_b: bytes
    digest: bytes
    hashes_computed: int   #how many messages we r hashing in total
    table_size: int        #how many fingerprints we have to store so i.e memory cost

def birthday_attack(n_bytes: int) -> BirthdayResult:
    prefix = os.urandom(8)
    seen = {}  #stores ur fingerprint and the msg that produced it
    counter = 0
    while True: #making every message in 1 run guaranteed to be different
        counter += 1
        message = prefix + counter.to_bytes(8, "big")
        digest = truncated_sha256(message, n_bytes)

        #hv we seen this fingerprint b4?
        earlier = seen.get(digest)
        if earlier is not None: #found collisions!!!!
            return BirthdayResult(earlier, message, digest, counter, len(seen))
        seen[digest] = message
