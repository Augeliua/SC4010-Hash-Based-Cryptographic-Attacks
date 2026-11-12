 # implementing lamport onetime signature

from dataclasses import dataclass
from hashlib import sha256 as _sha256
from secrets import token_bytes  # cryptographically secure random bytes for priv secrets
from typing import Callable

# the following hash functions will accept bytes and return digest bytes
# this will also let us swap full SHA-256 for a truncated toy hash
HashFn = Callable[[bytes], bytes]


def sha256_digest(data: bytes) -> bytes:
    # SHA-256 returns 32 bytes = 256 bits
    return _sha256(data).digest()


# for the purpose of toy experiements, we will use only the first digest_bytes of SHA-256
def sha256_truncated(data: bytes, digest_bytes: int = 32) -> bytes:
    if not 1 <= digest_bytes <= 32:
        raise ValueError("digest_bytes must be between 1 and 32")
    # eg: digest_bytes=2 gives a 16-bit hash, making attacks easier to test
    return sha256_digest(data)[:digest_bytes]


def message_bits(message: bytes, hash_fn: HashFn) -> tuple[int, ...]:
    # Lamport will now sign the bits of the message hash
    digest = hash_fn(message)
    if not digest:
        raise ValueError("hash output must be nonempty")

    # Convert every byte into eight 0/1 bits (eg. a byte 0b10110010 becomes (1, 0, 1, 1, 0, 0, 1, 0) )
    return tuple((byte >> bit) & 1 for byte in digest for bit in range(7, -1, -1))


@dataclass(frozen=True)
class LamportPrivateKey:
    # one pair per message-hash bit (ie secret for 0, secret for 1)
    # for SHA-256, 256 pairs = 512 random secrets 
    secrets: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class LamportPublicKey:
    # the corresponding hashes of all the secrets -> forms public key 
    hashes: tuple[tuple[bytes, bytes], ...]


def generate_keypair(hash_fn: HashFn = sha256_digest) -> tuple[LamportPrivateKey, LamportPublicKey]:
    # SHA-256 has a 32-BYTE digest, which contains 32 * 8 = 256 BITS.
    digest_size = len(hash_fn(b""))
    if digest_size == 0:
        raise ValueError("hash output must be nonempty")

    # now generate 2 independent secrets for each possible bit value (0 or 1).
    # note: for this implementation, we let digest_size = length of each random secret in bytes (32)
    # hence, with SHA-256: 256 pairs * 2 = 512 secrets, each 32 bytes long.

    pairs = tuple((token_bytes(digest_size), token_bytes(digest_size)) for _ in range(8 * digest_size))
    private = LamportPrivateKey(pairs)

    # publish the HASHES of all 512 secrets -> forms public key
    public = LamportPublicKey(tuple((hash_fn(zero), hash_fn(one)) for zero, one in pairs)) # 'zero' and 'one' are the two secrets at a particular bit position
    return private, public


def sign(message: bytes, private_key: LamportPrivateKey, hash_fn: HashFn = sha256_digest) -> tuple[bytes, ...]:
    # Step 1: hash the message and read its 0/1 bits.
    bits = message_bits(message, hash_fn)
    if len(bits) != len(private_key.secrets):
        raise ValueError("private key and hash function have incompatible lengths")

    # Step 2: for each bit position i, reveal the secret corresponding to the message hash bit:
    # ie if message hash bit=0 -> private_key.secrets[i][0]
    #    if message hash bit=1 -> private_key.secrets[i][1]

    # !!!! reusing this key for another message could reveal the other secret at some positions, giving an attacker material for a forgery
    return tuple(private_key.secrets[i][bit] for i, bit in enumerate(bits))


def verify(message: bytes, signature: tuple[bytes, ...], public_key: LamportPublicKey,
           hash_fn: HashFn = sha256_digest) -> bool:
    # Bob hashes the received message and reads its 0/1 bits
    bits = message_bits(message, hash_fn)

    # condi: a signature must contain one secret for every bit of the message hash
    if len(bits) != len(signature) or len(bits) != len(public_key.hashes):
        return False

    # Bob hashes each disclosed secret, then checks it against the matching public-key hash at position i and choice 'bit'
    return all(hash_fn(secret) == public_key.hashes[i][bit]     # 'all' means EVERY check must pass for the signature to be accepted
               for i, (bit, secret) in enumerate(zip(bits, signature)))
