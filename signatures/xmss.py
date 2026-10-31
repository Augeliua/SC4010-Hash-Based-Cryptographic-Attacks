"""Minimal stateful XMSS-style demo built on our educational WOTS+.

NOT RFC 8391 XMSS: deliberately stores all WOTS+ keys and uses a simple
Merkle construction. Demonstrates root/authentication paths/index/rollback.
"""
from dataclasses import dataclass
from hashlib import sha256
import hmac
from signatures.wots_plus import (WOTSPublicKey,
                                  generate_keypair as wots_keygen,
                                  sign as wots_sign, verify as wots_verify)


def leaf_hash(index: int, public: WOTSPublicKey) -> bytes:
    """Commit one WOTS+ public key to a specific leaf position."""
    # We include the public seed and all chain endpoints: they are needed to
    # verify an ordinary WOTS+ signature, and belong to THIS leaf only.
    content = (index.to_bytes(4, 'big') + public.n.to_bytes(2, 'big')
               + public.public_seed + b''.join(public.ends))
    return sha256(b'XMSS-TOY-LEAF' + content).digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    # Prefix separates internal Merkle nodes from leaves (domain separation).
    return sha256(b'XMSS-TOY-NODE' + left + right).digest()


@dataclass(frozen=True)
class XMSSPublicKey:
    root: bytes                  # ONE compact public commitment to all leaves
    height: int                  # 2**height one-time WOTS keys
    n: int


@dataclass(frozen=True)
class XMSSSignature:
    index: int                   # Which one-time key signed this message?
    wots_signature: tuple[bytes, ...]
    wots_public: WOTSPublicKey   # Educational simplification: include leaf key
    auth_path: tuple[bytes, ...] # Sibling hashes up to the Merkle root


class XMSSSigner:
    def __init__(self, height: int = 4, n: int = 2):
        if not 1 <= height <= 10:
            raise ValueError('height must be 1..10')
        if not 1 <= n <= 32:
            raise ValueError('n must be 1..32')
        self.height = height
        self.index = 0  # STATE: save this durably and NEVER move backwards!
        self._pairs = [wots_keygen(n) for _ in range(1 << height)]
        leaves = [leaf_hash(i, pub) for i, (_, pub) in enumerate(self._pairs)]
        self._levels = [leaves]
        # Pair adjacent hashes to build the Merkle tree, bottom-up.
        while len(self._levels[-1]) > 1:
            layer = self._levels[-1]
            self._levels.append([parent_hash(layer[i], layer[i+1])
                                 for i in range(0, len(layer), 2)])
        self.public = XMSSPublicKey(self._levels[-1][0], height, n)

    def authentication_path(self, index: int) -> tuple[bytes, ...]:
        # At each level, the sibling is index XOR 1 (flip its final bit).
        # Bob needs these siblings to rebuild the root from our chosen leaf.
        cursor = index
        siblings = []
        for level in self._levels[:-1]:
            siblings.append(level[cursor ^ 1])
            cursor //= 2
        return tuple(siblings)

    def sign(self, message: bytes) -> XMSSSignature:
        if self.index >= len(self._pairs):
            raise RuntimeError('All one-time signing keys have been used')
        index = self.index
        # Advance index BEFORE returning the signature. This protects normal
        # sequential use, but not an old backup that overwrites this value.
        self.index += 1
        private, public = self._pairs[index]
        return XMSSSignature(index, wots_sign(message, private), public,
                             self.authentication_path(index))

    def snapshot_state(self) -> int:
        # Simulates a backed-up, STALE next-unused index, not secret key backup.
        return self.index

    def restore_state_unchecked(self, saved_index: int) -> None:
        """INTENTIONALLY VULNERABLE restore for the rollback demonstration."""
        if not 0 <= saved_index <= len(self._pairs):
            raise ValueError('Invalid saved index')
        self.index = saved_index


def verify(message: bytes, signature: XMSSSignature,
           public: XMSSPublicKey) -> bool:
    """Check both WOTS+ authenticity AND Merkle membership against root."""
    if not isinstance(signature, XMSSSignature):
        return False
    idx = signature.index
    if not 0 <= idx < (1 << public.height):
        return False
    if len(signature.auth_path) != public.height:
        return False
    if signature.wots_public.n != public.n:
        return False
    if not wots_verify(message, signature.wots_signature, signature.wots_public):
        return False
    node = leaf_hash(idx, signature.wots_public)
    for sibling in signature.auth_path:
        if len(sibling) != 32:
            return False
        # Use leaf index bits to preserve LEFT/RIGHT ordering at each level.
        node = parent_hash(node, sibling) if idx % 2 == 0 else parent_hash(sibling, node)
        idx //= 2
    return hmac.compare_digest(node, public.root)
