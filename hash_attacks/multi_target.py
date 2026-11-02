#steal a Lamport key from its public key alone

import os
from dataclasses import dataclass

from hash_attacks.common import truncated_sha256
from signatures.lamport import LamportPrivateKey, LamportPublicKey


@dataclass
class CrackResult:
    recovered: dict           #(position, bit) i.e value with the right fingerprint
    total_targets: int
    guesses: int              
    first_hit_after: int      #guesses until the first target fell
    hit_log: list             #guesses count at each new crack (for the graphs)


def crack_public_key(public_key: LamportPublicKey, n_bytes: int,
                     max_guesses: int = None) -> CrackResult:
    #oputtin every public fingerprint into a dictionary
    #putting it in a list, because two slots could (rarely) share a fingerprint
    targets = {}
    for position, pair in enumerate(public_key.hashes):
        for bit, fingerprint in enumerate(pair):
            targets.setdefault(fingerprint, []).append((position, bit))
    total = sum(len(slots) for slots in targets.values())

    # guessing values by random prefix + counter
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
            #success!!
            for slot in slots:
                recovered[slot] = guess
                hit_log.append(guesses)
            del targets[truncated_sha256(guess, n_bytes)]

    return CrackResult(recovered, total, guesses,
                       hit_log[0] if hit_log else None, hit_log)


def forged_private_key(result: CrackResult, n_positions: int) -> LamportPrivateKey:
    return LamportPrivateKey(tuple((result.recovered[(i, 0)], result.recovered[(i, 1)])
                                   for i in range(n_positions)))

#measuring when the first secret falls
def guesses_until_first_hit(target_count: int, n_bytes: int) -> int:
    targets = {os.urandom(n_bytes) for _ in range(target_count)}
    prefix = os.urandom(8)
    guesses = 0
    while True:
        guesses += 1
        if truncated_sha256(prefix + guesses.to_bytes(8, "big"), n_bytes) in targets:
            return guesses
