"""Educational WOTS+-style signatures (NOT an RFC 8391 implementation).

We preserve the essential WOTS+ ideas: independent secret chain starts,
address/step-dependent keyed and masked hash chains, base-16 digits, and a
checksum. We simplify RFC 8391's PRF/address format and message processing.
Never use these signatures to protect real data or reuse a signing key.
"""
from dataclasses import dataclass
from hashlib import sha256
import hmac
from secrets import token_bytes

W = 16  # A hex digit represents 4 bits; each chain has positions 0..15.


@dataclass(frozen=True)
class WOTSPrivateKey:
    starts: tuple[bytes, ...]
    public_seed: bytes
    n: int


@dataclass(frozen=True)
class WOTSPublicKey:
    ends: tuple[bytes, ...]
    public_seed: bytes
    n: int


def lengths(n: int) -> tuple[int, int]:
    """How many message digits and checksum digits do we need?"""
    if not 1 <= n <= 32:
        raise ValueError('n must be between 1 and 32 bytes')
    len1 = 2 * n  # Two hex digits per byte, e.g. 0xA3 -> [10, 3].
    maximum_checksum = len1 * (W - 1)
    len2 = 1
    while W ** len2 <= maximum_checksum:
        len2 += 1
    return len1, len2


def base16_digits(message: bytes, n: int) -> tuple[int, ...]:
    """Hash the message; convert each digest nibble to an integer 0..15."""
    digest = sha256(message).digest()[:n]
    return tuple(int(char, 16) for char in digest.hex())


def checksum_digits(message_digits: tuple[int, ...], len2: int) -> tuple[int, ...]:
    """Add unused chain steps; encode the total in base 16."""
    checksum = sum(15 - digit for digit in message_digits)
    # Left pad with zero digits, so every signature has the same layout.
    digits = [0] * len2
    for i in range(len2 - 1, -1, -1):
        digits[i] = checksum % 16
        checksum //= 16
    if checksum:
        raise ValueError('Checksum does not fit')
    return tuple(digits)


def signing_digits(message: bytes, n: int) -> tuple[int, ...]:
    """Both message and checksum digits get their own hash chains."""
    message_part = base16_digits(message, n)
    _, len2 = lengths(n)
    return message_part + checksum_digits(message_part, len2)


def _prf(seed: bytes, chain_idx: int, step_idx: int, domain: bytes, n: int) -> bytes:
    # Domain separation: a different derived value for key vs mask.
    address = chain_idx.to_bytes(4, 'big') + step_idx.to_bytes(4, 'big')
    return hmac.new(seed, domain + address, 'sha256').digest()[:n]


def chain(value: bytes, start: int, steps: int, chain_idx: int,
          public_seed: bytes, n: int) -> bytes:
    """Move FORWARD along one chain, never backward."""
    if len(value) != n or start < 0 or steps < 0 or start + steps > W - 1:
        raise ValueError('Invalid chain parameters')
    current = value
    for step in range(start, start + steps):
        # The public seed, chain number, and step determine a fresh key/mask.
        key = _prf(public_seed, chain_idx, step, b'key', n)
        mask = _prf(public_seed, chain_idx, step, b'mask', n)
        masked = bytes(a ^ b for a, b in zip(current, mask))
        current = sha256(key + masked).digest()[:n]
    return current


def generate_keypair(n: int = 32) -> tuple[WOTSPrivateKey, WOTSPublicKey]:
    """Alice picks one random START per chain; Bob knows only the ENDS."""
    len1, len2 = lengths(n)
    starts = tuple(token_bytes(n) for _ in range(len1 + len2))
    seed = token_bytes(32)  # Public: lets Bob reproduce chain step keys/masks.
    ends = tuple(chain(start, 0, 15, i, seed, n)
                 for i, start in enumerate(starts))
    return WOTSPrivateKey(starts, seed, n), WOTSPublicKey(ends, seed, n)


def sign(message: bytes, private: WOTSPrivateKey) -> tuple[bytes, ...]:
    """Reveal the chain node at each message/checksum digit's position."""
    digits = signing_digits(message, private.n)
    if len(digits) != len(private.starts):
        raise ValueError('Private key has incorrect chain count')
    return tuple(chain(start, 0, digit, i, private.public_seed, private.n)
                 for i, (start, digit) in enumerate(zip(private.starts, digits)))


def verify(message: bytes, signature: tuple[bytes, ...],
           public: WOTSPublicKey) -> bool:
    """Bob advances each revealed node to its public endpoint and compares."""
    digits = signing_digits(message, public.n)
    if len(signature) != len(public.ends) or len(digits) != len(signature):
        return False
    if any(len(node) != public.n for node in signature):
        return False
    for i, (node, digit) in enumerate(zip(signature, digits)):
        # Alice already took 'digit' steps. Bob takes the remaining 15-digit.
        endpoint = chain(node, digit, 15 - digit, i, public.public_seed, public.n)
        if not hmac.compare_digest(endpoint, public.ends[i]):
            return False
    return True
