#shared helpers
#we're gg be using the same toy hash as signatures
#must use same fn as angelina cause collision here means must also b collision for her sign

#truncate in whole bytes cause her truncated also works in bytes!!

from functools import partial
from hashlib import sha256
from math import pi, sqrt

from signatures.lamport import sha256_truncated

#truncate first n bytes
def truncated_sha256(data: bytes, n_bytes: int) -> bytes:
    return sha256(data).digest()[:n_bytes]

#return the exact hash fn to pass into her generate sign/verify
def lamport_hash(n_bytes: int):
    return partial(sha256_truncated, digest_bytes=n_bytes)

#creates the theoritical line on the graph
def expected_collision_work(n_bits: int) -> float:
    return sqrt(pi / 2 * 2 ** n_bits)
