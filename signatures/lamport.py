"""Educational Lamport one-time signatures. Do not reuse a private key."""
from dataclasses import dataclass
from hashlib import sha256 as _sha256
from secrets import token_bytes
from typing import Callable

HashFn = Callable[[bytes], bytes]


def sha256_digest(data: bytes) -> bytes:
    return _sha256(data).digest()


def sha256_truncated(data: bytes, digest_bytes: int = 32) -> bytes:
    """SHA-256 with a byte-truncated digest (for educational experiments)."""
    if not 1 <= digest_bytes <= 32:
        raise ValueError("digest_bytes must be between 1 and 32")
    return sha256_digest(data)[:digest_bytes]


def message_bits(message: bytes, hash_fn: HashFn) -> tuple[int, ...]:
    digest = hash_fn(message)
    if not digest:
        raise ValueError("hash output must be nonempty")
    return tuple((byte >> bit) & 1 for byte in digest for bit in range(7, -1, -1))


@dataclass(frozen=True)
class LamportPrivateKey:
    secrets: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class LamportPublicKey:
    hashes: tuple[tuple[bytes, bytes], ...]


def generate_keypair(hash_fn: HashFn = sha256_digest) -> tuple[LamportPrivateKey, LamportPublicKey]:
    digest_size = len(hash_fn(b""))
    if digest_size == 0:
        raise ValueError("hash output must be nonempty")
    pairs = tuple((token_bytes(digest_size), token_bytes(digest_size)) for _ in range(8 * digest_size))
    private = LamportPrivateKey(pairs)
    public = LamportPublicKey(tuple((hash_fn(zero), hash_fn(one)) for zero, one in pairs))
    return private, public


def sign(message: bytes, private_key: LamportPrivateKey, hash_fn: HashFn = sha256_digest) -> tuple[bytes, ...]:
    bits = message_bits(message, hash_fn)
    if len(bits) != len(private_key.secrets):
        raise ValueError("private key and hash function have incompatible lengths")
    return tuple(private_key.secrets[i][bit] for i, bit in enumerate(bits))


def verify(message: bytes, signature: tuple[bytes, ...], public_key: LamportPublicKey,
           hash_fn: HashFn = sha256_digest) -> bool:
    bits = message_bits(message, hash_fn)
    if len(bits) != len(signature) or len(bits) != len(public_key.hashes):
        return False
    return all(hash_fn(secret) == public_key.hashes[i][bit]
               for i, (bit, secret) in enumerate(zip(bits, signature)))
