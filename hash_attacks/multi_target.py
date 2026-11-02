"""Multi-target preimage attack: steal a Lamport key from its PUBLIC key alone.

A Lamport public key is a list of fingerprints H(secret). verify() only ever
checks H(revealed_value) == public fingerprint. So ANY value with the right
fingerprint works as that secret, not just Alice's original one. Finding such
a value is a "preimage attack".

ONE target: about 2^n guesses (each guess matches with probability 1/2^n).
T targets:  each guess is checked against ALL of them at once (a set lookup
            is as fast as checking one), so it matches SOME target with
            probability T/2^n. The first hit needs only about 2^n / T guesses.

A Lamport key with an n-bit hash has 2n fingerprints, so the attacker gets a
2n-times speedup for free. Recovering EVERY secret costs about
2^n * (1 + 1/2 + ... + 1/2n), roughly 2^n * ln(2n), only a few times more than
cracking one. With every secret recovered, the attacker can sign ANY message
without ever seeing a signature (universal forgery).

Real schemes (WOTS+, SPHINCS+) defend against this by mixing a different
random mask or "tweak" into every hash call, so each guess can only ever
match one target.

Note: with her current lamport.py, the same truncated hash is used for the
message digest and the key fingerprints, so an n-bit hash gives 2n targets.
"""
import os
from dataclasses import dataclass

from hash_attacks.common import truncated_sha256
from signatures.lamport import LamportPrivateKey, LamportPublicKey


@dataclass
class CrackResult:
    recovered: dict           # (position, bit) -> a value with the right fingerprint
    total_targets: int
    guesses: int              # total guesses made
    first_hit_after: int      # guesses until the FIRST target fell
    hit_log: list             # guesses count at each new crack (for plots)


def crack_public_key(public_key: LamportPublicKey, n_bytes: int,
                     max_guesses: int = None) -> CrackResult:
    # 1. Put every public fingerprint into a dictionary:
    #    fingerprint -> list of (position, bit) slots that use it.
    #    A list, because two slots could (rarely) share a fingerprint.
    targets = {}
    for position, pair in enumerate(public_key.hashes):
        for bit, fingerprint in enumerate(pair):
            targets.setdefault(fingerprint, []).append((position, bit))
    total = sum(len(slots) for slots in targets.values())

    # 2. Guess values and hash them. Random prefix + counter: every guess is
    #    different and runs are independent.
    prefix = os.urandom(8)
    recovered, hit_log = {}, []
    guesses = 0
    while len(recovered) < total:
        if max_guesses is not None and guesses >= max_guesses:
            break
        guesses += 1
        guess = prefix + guesses.to_bytes(8, "big")
        slots = targets.get(truncated_sha256(guess, n_bytes))
        if slots:
            # 3. Hit! This guess works as the secret for every matching slot.
            for slot in slots:
                recovered[slot] = guess
                hit_log.append(guesses)
            del targets[truncated_sha256(guess, n_bytes)]

    return CrackResult(recovered, total, guesses,
                       hit_log[0] if hit_log else None, hit_log)


def forged_private_key(result: CrackResult, n_positions: int) -> LamportPrivateKey:
    """Assemble the recovered values into her LamportPrivateKey class.

    The result is NOT Alice's real key (the values differ), but her verify()
    cannot tell the difference, so her sign() can use it to sign anything.
    """
    return LamportPrivateKey(tuple((result.recovered[(i, 0)], result.recovered[(i, 1)])
                                   for i in range(n_positions)))


def guesses_until_first_hit(target_count: int, n_bytes: int) -> int:
    """Experiment helper: how long until ANY of target_count random targets falls?"""
    targets = {os.urandom(n_bytes) for _ in range(target_count)}
    prefix = os.urandom(8)
    guesses = 0
    while True:
        guesses += 1
        if truncated_sha256(prefix + guesses.to_bytes(8, "big"), n_bytes) in targets:
            return guesses
