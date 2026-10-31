"""Length extension attack on FULL-SIZE SHA-256 (no truncation).

A naive server authenticates messages with
    tag = SHA-256(secret_key || message)
The attacker sees one (message, tag) pair but NOT the key. They can still
produce a valid tag for
    message || padding || anything_they_want
without ever learning the key.

WHY IT WORKS
SHA-256 processes data in 64-byte blocks, carrying a 32-byte internal
"state" from block to block. The final output IS just that state. So a tag
tells the attacker the exact state the machine was in after the last block
of (key || message || padding). The attacker loads that state into their own
SHA-256 and keeps hashing extra blocks, as if they were the server.

The only thing they must guess is the key LENGTH (needed to rebuild the
padding), and they can simply try every length from 1 to 64.

THE FIX: use HMAC, which hashes twice with the key on the outside, or a hash
like SHA-3 whose output is not its full internal state.

We need our own SHA-256 because hashlib cannot start from a custom state.
tests/test_hash_attacks.py checks our version against hashlib.
"""
import hmac
import struct
from hashlib import sha256

# --- SHA-256 from scratch (FIPS 180-4). Constants are from the standard. ---
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
_INITIAL_STATE = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
_MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state, block):
    """Mix one 64-byte block into the 8-word state. This is SHA-256's core."""
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25))
              + ((e & f) ^ (~e & g)) + _K[i] + w[i]) & _MASK
        t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22))
              + ((a & b) ^ (a & c) ^ (b & c))) & _MASK
        a, b, c, d, e, f, g, h = (t1 + t2) & _MASK, a, b, c, (d + t1) & _MASK, e, f, g
    return tuple((x + y) & _MASK for x, y in zip(state, (a, b, c, d, e, f, g, h)))


def sha256_padding(message_length: int) -> bytes:
    """The padding SHA-256 appends: 0x80, zeros, then the length in bits.

    It always brings the total length to a multiple of 64 bytes.
    """
    zeros = (55 - message_length) % 64
    return b"\x80" + b"\x00" * zeros + struct.pack(">Q", 8 * message_length)


def sha256_resume(data: bytes, state=_INITIAL_STATE, already_hashed: int = 0) -> bytes:
    """SHA-256 that can start from ANY state, as if already_hashed bytes
    (including their padding) had been processed. With the defaults it is
    ordinary SHA-256."""
    padded = data + sha256_padding(already_hashed + len(data))
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i:i + 64])
    return struct.pack(">8I", *state)


# --- The vulnerable server and the attack ---------------------------------
class NaiveServer:
    """Authenticates messages with SHA-256(key || message). Vulnerable."""

    def __init__(self, key: bytes):
        self._key = key  # the attacker never sees this

    def tag(self, message: bytes) -> bytes:
        return sha256(self._key + message).digest()

    def accepts(self, message: bytes, tag: bytes) -> bool:
        return hmac.compare_digest(self.tag(message), tag)


def extend(message: bytes, tag: bytes, extra: bytes, key_length: int):
    """Forge (new_message, new_tag) using only the public message and tag."""
    # 1. The padding the server's SHA-256 added after key || message.
    #    The attacker can compute it because it depends only on the LENGTH.
    glue = sha256_padding(key_length + len(message))
    # 2. Unpack the tag back into SHA-256's 8-word internal state.
    state = struct.unpack(">8I", tag)
    # 3. Continue hashing `extra` from that state, telling SHA-256 how many
    #    bytes were already processed (so the final length field is right).
    already = key_length + len(message) + len(glue)
    new_tag = sha256_resume(extra, state, already)
    # 4. The server will hash key || message || glue || extra and get new_tag.
    return message + glue + extra, new_tag


def attack_unknown_key_length(server: NaiveServer, message: bytes, tag: bytes,
                              extra: bytes, max_key_length: int = 64):
    """Try every key length; return (key_length, forged_message, forged_tag)."""
    for key_length in range(1, max_key_length + 1):
        forged_message, forged_tag = extend(message, tag, extra, key_length)
        if server.accepts(forged_message, forged_tag):
            return key_length, forged_message, forged_tag
    return None
