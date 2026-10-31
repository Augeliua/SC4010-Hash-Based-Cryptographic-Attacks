"""Lamport one-time signatures for SC4010 learning and attack experiments.

The idea: Alice keeps random secrets private, publishes their hashes, and
reveals selected secrets to sign a message. One key pair should sign ONE
message only; later milestones deliberately violate this to demonstrate why.

Educational code, not a production-ready signature implementation.
"""

from dataclasses import dataclass
from hashlib import sha256 as _sha256
from secrets import token_bytes  # Cryptographically secure random bytes for private secrets.
from typing import Callable

# Every hash function in our project accepts bytes and returns digest bytes.
# This also lets us swap full SHA-256 for a deliberately truncated toy hash.
HashFn = Callable[[bytes], bytes]


def sha256_digest(data: bytes) -> bytes:
    # SHA-256 returns 32 bytes = 256 bits, regardless of the input length.
    # .digest() gives us the actual bytes, not a printable hexadecimal string.
    return _sha256(data).digest()


def sha256_truncated(data: bytes, digest_bytes: int = 32) -> bytes:
    """Keep only the first digest_bytes of SHA-256 for toy experiments."""
    if not 1 <= digest_bytes <= 32:
        raise ValueError("digest_bytes must be between 1 and 32")
    # Example: digest_bytes=2 gives a 16-bit hash, making attacks easier to test.
    # This is intentionally weaker than ordinary SHA-256.
    return sha256_digest(data)[:digest_bytes]


def message_bits(message: bytes, hash_fn: HashFn) -> tuple[int, ...]:
    # Lamport signs the BITS of the message hash, not the message's letters.
    digest = hash_fn(message)
    if not digest:
        raise ValueError("hash output must be nonempty")

    # Convert every byte into eight 0/1 bits (leftmost bit first).
    # For example, a byte 0b10110010 becomes (1, 0, 1, 1, 0, 0, 1, 0).
    # '>> bit' shifts a particular bit to the right; '& 1' extracts it.
    return tuple((byte >> bit) & 1 for byte in digest for bit in range(7, -1, -1))


@dataclass(frozen=True)
class LamportPrivateKey:
    # One PAIR per message-hash bit: (secret for 0, secret for 1).
    # With SHA-256: 256 pairs = 512 random secrets in total.
    secrets: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class LamportPublicKey:
    # The corresponding hashes of BOTH secrets in each pair.
    # Bob can check a revealed secret without knowing unrevealed secrets.
    hashes: tuple[tuple[bytes, bytes], ...]


def generate_keypair(hash_fn: HashFn = sha256_digest) -> tuple[LamportPrivateKey, LamportPublicKey]:
    # SHA-256 has a 32-BYTE digest, which contains 32 * 8 = 256 BITS.
    digest_size = len(hash_fn(b""))
    if digest_size == 0:
        raise ValueError("hash output must be nonempty")

    # IMPORTANT: These are two different quantities:
    #   8 * digest_size  = number of BIT POSITIONS / secret PAIRS (256).
    #   digest_size      = length of EACH random secret in bytes (32).
    # We generate two independent secrets for each possible bit value (0 or 1).
    # Example with SHA-256: 256 pairs * 2 = 512 secrets, each 32 bytes long.
    # Using 32-byte secrets is this implementation's choice; SHA-256 does not
    # require that inputs to the hash function be exactly 32 bytes long.
    pairs = tuple((token_bytes(digest_size), token_bytes(digest_size)) for _ in range(8 * digest_size))
    private = LamportPrivateKey(pairs)

    # Publish the HASHES of all 512 secrets, not the secrets themselves.
    # 'zero' and 'one' are the two secrets at a particular bit position.
    public = LamportPublicKey(tuple((hash_fn(zero), hash_fn(one)) for zero, one in pairs))
    return private, public


def sign(message: bytes, private_key: LamportPrivateKey, hash_fn: HashFn = sha256_digest) -> tuple[bytes, ...]:
    # Step 1: Hash the message and read its individual 0/1 bits.
    bits = message_bits(message, hash_fn)
    if len(bits) != len(private_key.secrets):
        raise ValueError("private key and hash function have incompatible lengths")

    # Step 2: For each bit position i, reveal exactly ONE secret:
    #   bit=0 -> private_key.secrets[i][0]
    #   bit=1 -> private_key.secrets[i][1]
    # Thus a SHA-256 Lamport signature contains 256 secrets (not 512).
    # WARNING: Reusing this key for another message could reveal the other
    # secret at some positions, giving an attacker material for a forgery.
    return tuple(private_key.secrets[i][bit] for i, bit in enumerate(bits))


def verify(message: bytes, signature: tuple[bytes, ...], public_key: LamportPublicKey,
           hash_fn: HashFn = sha256_digest) -> bool:
    # Bob hashes the received message to determine which secret SHOULD have
    # been revealed at every bit position.
    bits = message_bits(message, hash_fn)

    # A signature must contain one secret for every bit of the message hash.
    if len(bits) != len(signature) or len(bits) != len(public_key.hashes):
        return False

    # Bob hashes each disclosed secret, then checks it against the matching
    # public-key hash at position i and choice 'bit'.
    # 'all' means EVERY check must pass for the signature to be accepted.
    return all(hash_fn(secret) == public_key.hashes[i][bit]
               for i, (bit, secret) in enumerate(zip(bits, signature)))
