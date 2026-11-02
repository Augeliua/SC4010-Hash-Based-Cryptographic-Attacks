"""Pollard's rho collision search: birthday-speed, but almost no memory.

THE IDEA
Treat the hash as a step function on n-bit values: x -> f(x) = H(x).
Start anywhere and keep stepping: x0, f(x0), f(f(x0)), ...
There are only 2^n possible values, so the walk must eventually revisit one
and loop forever. The path looks like the Greek letter rho: a tail, then a
loop. Where the tail joins the loop, two DIFFERENT values step to the same
next value. That is a collision: f(a) == f(b) with a != b.
The tail plus loop is about 1.25 * 2^(n/2) steps long, same as the birthday
attack, but we never store a table.

TWO VERSIONS
1. floyd_rho: the classic tortoise-and-hare loop finder. One core, O(1) memory.
2. distinguished_point_rho: many independent walks in parallel (one per CPU
   core). Each walk only reports special "landmark" values, called
   distinguished points (DPs): values whose top dp_bits bits are all zero.
   If two walks ever hit the same value, they follow the same path from then
   on and arrive at the SAME landmark. Seeing a landmark twice tells us two
   walks merged, and we rewalk both to find the exact merge point.
   This is the van Oorschot-Wiener method used for real cryptanalysis.

STEP FUNCTIONS
StepFunction(n_bytes) is plain rho: f(x) = H(x), so the colliding values are
random-looking bytes. Passing an encoder (see meaningful_collision.py) makes
f(x) = H(encoder(x)), so each value x stands for a readable message.
"""
import os
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from hashlib import sha256

from hash_attacks.common import expected_collision_work


class StepFunction:
    """f(x) = first n_bytes of SHA-256(encoder(x)).

    Input and output are both n_bytes long, so we can keep feeding the output
    back in as the next input. It is a class (not a lambda) so that
    multiprocessing can send it to worker processes.
    """

    def __init__(self, n_bytes: int, encoder=None):
        self.n_bytes = n_bytes
        self.encoder = encoder  # None means "hash x itself"

    def message(self, x: bytes) -> bytes:
        """The actual message that gets hashed for value x."""
        return x if self.encoder is None else self.encoder(x)

    def __call__(self, x: bytes) -> bytes:
        return sha256(self.message(x)).digest()[:self.n_bytes]


@dataclass
class RhoResult:
    value_a: bytes          # f(value_a) == f(value_b), value_a != value_b
    value_b: bytes
    message_a: bytes        # the real colliding messages (encoder applied)
    message_b: bytes
    digest: bytes
    hash_evaluations: int   # total work, counted in hash calls
    stored_points: int = 0  # memory used (number of landmarks stored)
    extra: dict = field(default_factory=dict)


def _result(step, a, b, evaluations, stored=0, **extra):
    return RhoResult(a, b, step.message(a), step.message(b), step(a),
                     evaluations, stored, extra)


# ---------------------------------------------------------------------------
# Version 1: Floyd's tortoise and hare
# ---------------------------------------------------------------------------
def floyd_rho(step: StepFunction) -> RhoResult:
    evaluations = 0
    while True:
        x0 = os.urandom(step.n_bytes)

        # Phase 1: tortoise moves 1 step, hare moves 2. Once both are inside
        # the loop, the hare gains 1 step per round and must catch up.
        tortoise, hare = step(x0), step(step(x0))
        evaluations += 3
        while tortoise != hare:
            tortoise = step(tortoise)
            hare = step(step(hare))
            evaluations += 3

        # Phase 2: send the tortoise back to the start and move both 1 step
        # at a time. Maths fact: they now meet exactly at the loop entrance.
        # We stop one step EARLY: the two values just before the entrance
        # (one on the tail, one on the loop) are different but step to the
        # same value. That pair is our collision.
        tortoise = x0
        if tortoise == hare:
            continue  # x0 was already on the loop: no tail, no collision. Retry.
        while True:
            next_t, next_h = step(tortoise), step(hare)
            evaluations += 2
            if next_t == next_h:
                return _result(step, tortoise, hare, evaluations)
            tortoise, hare = next_t, next_h


# ---------------------------------------------------------------------------
# Version 2: parallel distinguished-point rho
# ---------------------------------------------------------------------------
def default_dp_bits(n_bits: int) -> int:
    """How rare landmarks are. One in 2^dp_bits values is a landmark.

    Expected total work is about 2^(n/2), so we store about
    2^(n/2) / 2^dp_bits landmarks. n/2 - 9 keeps that around a few hundred:
    tiny memory, but walks are still short enough to spread across cores.
    """
    return max(2, n_bits // 2 - 9) if n_bits >= 24 else 2


def _is_distinguished(x: bytes, dp_bits: int) -> bool:
    # Read the first (up to) 4 bytes as a number and check its top dp_bits
    # bits are all zero.
    head = x[:4]
    return int.from_bytes(head, "big") >> (8 * len(head) - dp_bits) == 0


def _walk_trails(step: StepFunction, dp_bits: int, step_budget: int):
    """Worker job: walk from random starts until each walk hits a landmark.

    Returns a list of (landmark, start, length), plus the hash evaluations
    wasted on walks we abandoned. Runs inside a separate process.
    """
    max_length = 20 << dp_bits  # give up on walks stuck in a landmark-free loop
    trails, used, wasted = [], 0, 0
    while used < step_budget:
        start = x = os.urandom(step.n_bytes)
        length = 0
        while not _is_distinguished(x, dp_bits) and length < max_length:
            x = step(x)
            length += 1
        used += length
        if 0 < length < max_length:
            trails.append((x, start, length))
        else:
            wasted += length
    return trails, wasted


def recover_collision(step, start_1, length_1, start_2, length_2):
    """Two walks reached the same landmark: find exactly where they merged.

    Returns (a, b, evaluations) with f(a) == f(b), or None if one start point
    simply lay on the other walk (no real collision, the "Robin Hood" case).
    """
    a, b, evaluations = start_1, start_2, 0
    # 1. Line the walks up: advance the longer one until both are the same
    #    number of steps away from the landmark.
    if length_1 < length_2:
        a, b, length_1, length_2 = b, a, length_2, length_1
    for _ in range(length_1 - length_2):
        a = step(a)
        evaluations += 1
    if a == b:
        return None  # same walk, not a collision
    # 2. Step both together. The last values BEFORE they become equal are two
    #    different inputs with the same hash.
    while True:
        next_a, next_b = step(a), step(b)
        evaluations += 2
        if next_a == next_b:
            return a, b, evaluations
        a, b = next_a, next_b


def distinguished_point_rho(step: StepFunction, workers: int = None,
                            dp_bits: int = None):
    """Generator that yields collisions forever (stop it with break).

    It yields more than one collision because meaningful_collision.py may
    need to skip some (for example, two versions of the same $10 contract).
    """
    workers = workers or os.cpu_count() or 1
    if dp_bits is None:
        dp_bits = default_dp_bits(8 * step.n_bytes)
    # Job size: small enough that results come back often (so we notice a
    # collision soon after it happens), big enough that process overhead
    # stays small. Roughly 1/64 of the expected total work, split over cores.
    expected = expected_collision_work(8 * step.n_bytes)
    budget = int(min(1 << 18, max(4 << dp_bits, expected / (64 * workers))))

    landmarks = {}      # landmark -> (start, length) of the first walk to reach it
    evaluations = 0
    seen_pairs = set()  # avoid reporting the same collision twice

    def handle(trails):
        nonlocal evaluations
        found = []
        for landmark, start, length in trails:
            # Count work walk by walk, so a collision is credited with only
            # the hashes done up to the walk that revealed it.
            evaluations += length
            earlier = landmarks.get(landmark)
            if earlier is None:
                landmarks[landmark] = (start, length)
                continue
            if earlier[0] == start:
                continue
            recovered = recover_collision(step, earlier[0], earlier[1], start, length)
            if recovered is None:
                continue
            a, b, cost = recovered
            evaluations += cost
            key = frozenset((a, b))
            if key not in seen_pairs:
                seen_pairs.add(key)
                found.append((a, b))
        return found

    # workers == 1: run everything in this process (simpler, used by tests).
    if workers == 1:
        while True:
            trails, wasted = _walk_trails(step, dp_bits, budget)
            evaluations += wasted
            for a, b in handle(trails):
                yield _result(step, a, b, evaluations, len(landmarks),
                              dp_bits=dp_bits, workers=1)

    # workers > 1: keep one job running per core. As each job finishes,
    # check its landmarks and immediately start a replacement job.
    executor = ProcessPoolExecutor(max_workers=workers)
    try:
        pending = {executor.submit(_walk_trails, step, dp_bits, budget)
                   for _ in range(workers)}
        while True:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for job in done:
                trails, wasted = job.result()
                evaluations += wasted
                pending.add(executor.submit(_walk_trails, step, dp_bits, budget))
                for a, b in handle(trails):
                    yield _result(step, a, b, evaluations, len(landmarks),
                                  dp_bits=dp_bits, workers=workers)
    finally:
        # Runs when the caller stops the generator: kill remaining jobs.
        executor.shutdown(wait=False, cancel_futures=True)


def find_collision(n_bytes: int, workers: int = None, dp_bits: int = None) -> RhoResult:
    """Convenience wrapper: first collision for the plain truncated hash."""
    gen = distinguished_point_rho(StepFunction(n_bytes), workers, dp_bits)
    result = next(gen)
    gen.close()
    return result
