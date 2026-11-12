#  implementing a minimal XMSS style signature scheme built on the WOTS+ implementation  

from dataclasses import dataclass
from hashlib import sha256
import hmac
from signatures.wots_plus import (WOTSPublicKey,
                                  generate_keypair as wots_keygen,
                                  sign as wots_sign, verify as wots_verify)


def leaf_hash(index: int, public: WOTSPublicKey) -> bytes:
    # hash each WOTS+ public key into a leaf
    content = (index.to_bytes(4, 'big') + public.n.to_bytes(2, 'big')
               + public.public_seed + b''.join(public.ends))
    return sha256(b'XMSS-TOY-LEAF' + content).digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    # repeatedly combines pairs of hashes to produce one merkle root
    return sha256(b'XMSS-TOY-NODE' + left + right).digest()


@dataclass(frozen=True)
class XMSSPublicKey:
    root: bytes                  
    height: int                  # 2**height one-time WOTS keys
    n: int


@dataclass(frozen=True)
class XMSSSignature:
    index: int                   # which one-time key signed this message?
    wots_signature: tuple[bytes, ...]
    wots_public: WOTSPublicKey   
    auth_path: tuple[bytes, ...] # sibling hashes up to the Merkle root


class XMSSSigner:
    def __init__(self, height: int = 4, n: int = 2):
        if not 1 <= height <= 10:
            raise ValueError('height must be 1..10')
        if not 1 <= n <= 32:
            raise ValueError('n must be 1..32')
        self.height = height
        self.index = 0  
        self._pairs = [wots_keygen(n) for _ in range(1 << height)]
        leaves = [leaf_hash(i, pub) for i, (_, pub) in enumerate(self._pairs)]
        self._levels = [leaves]
        # pair adjacent hashes to build the Merkle tree, bottom-up.
        while len(self._levels[-1]) > 1:
            layer = self._levels[-1]
            self._levels.append([parent_hash(layer[i], layer[i+1])
                                 for i in range(0, len(layer), 2)])
        self.public = XMSSPublicKey(self._levels[-1][0], height, n)

    # collect one sibling hash per tree level, allowing Bob to reconstruct the Merkle root  
    def authentication_path(self, index: int) -> tuple[bytes, ...]:
        # at each level, the sibling is index XOR 1 (flip its final bit).
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
        # advance index before returning the signature
        self.index += 1
        private, public = self._pairs[index]
        return XMSSSignature(index, wots_sign(message, private), public,
                             self.authentication_path(index))

    def snapshot_state(self) -> int:
        # simulates a backed-up, stale next-unused index.
        return self.index

    def restore_state_unchecked(self, saved_index: int) -> None:
        # note: this is intentionally vulnerable to demonstrate a rollback attack 
        if not 0 <= saved_index <= len(self._pairs):
            raise ValueError('Invalid saved index')
        self.index = saved_index


def verify(message: bytes, signature: XMSSSignature,
           public: XMSSPublicKey) -> bool:
    # Bob checks both WOTS+ authenticity and Merkle membership against root
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
        # use leaf index bits to preserve LEFT/RIGHT ordering at each level.
        node = parent_hash(node, sibling) if idx % 2 == 0 else parent_hash(sibling, node)
        idx //= 2
    return hmac.compare_digest(node, public.root)
