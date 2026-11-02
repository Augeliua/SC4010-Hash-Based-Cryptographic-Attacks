#pollards rho so no memory!!!
#need to use hash as step fn

#using 2 versions here --
    #floyd_rho the classic one we learnt in class
    #distinguished point rho -- several independant walks in parallel, if 2 hit th esame value they follow same path and hit same landmrark
import os
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from hashlib import sha256

from hash_attacks.common import expected_collision_work

#we seein first n bytes of sha-256
class StepFunction:

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
    value_a: bytes          
    value_b: bytes
    message_a: bytes        #the real colliding messages
    message_b: bytes
    digest: bytes
    hash_evaluations: int   #total work - be counted in hash calls
    stored_points: int = 0  #the memory used i.enumber of landmarks stored
    extra: dict = field(default_factory=dict)


def _result(step, a, b, evaluations, stored=0, **extra):
    return RhoResult(a, b, step.message(a), step.message(b), step(a),
                     evaluations, stored, extra)


#ver 1: floyds tortise and hare
def floyd_rho(step: StepFunction) -> RhoResult:
    evaluations = 0
    while True:
        x0 = os.urandom(step.n_bytes)
        tortoise, hare = step(x0), step(step(x0))
        evaluations += 3
        while tortoise != hare:
            tortoise = step(tortoise)
            hare = step(step(hare))
            evaluations += 3

        tortoise = x0
        if tortoise == hare:
            continue  #x0 was alr on the loop: no tail, no collision -- so we retry
        while True:
            next_t, next_h = step(tortoise), step(hare)
            evaluations += 2
            if next_t == next_h:
                return _result(step, tortoise, hare, evaluations)
            tortoise, hare = next_t, next_h


#version 2- parallel distinguished point rho
def default_dp_bits(n_bits: int) -> int:
    return max(2, n_bits // 2 - 9) if n_bits >= 24 else 2


def _is_distinguished(x: bytes, dp_bits: int) -> bool:
    head = x[:4] #read up to first 4 bytes
    return int.from_bytes(head, "big") >> (8 * len(head) - dp_bits) == 0


def _walk_trails(step: StepFunction, dp_bits: int, step_budget: int):
    #returns list of landmark, start, length

    max_length = 20 << dp_bits  
    trails, used, wasted = [], 0, 0
    while used < step_budget:
        start = x = os.urandom(step.n_bytes)
        length = 0
        #while ure at landmark and hvnt hit the limit--
        while not _is_distinguished(x, dp_bits) and length < max_length:
            x = step(x)
            length += 1 #increase step
        used += length
        if 0 < length < max_length:
            trails.append((x, start, length))
        else:
            wasted += length
    return trails, wasted

#find exactly where the walks merged
def recover_collision(step, start_1, length_1, start_2, length_2):
    #impt --- returns none if one start point simply lay on the other walk (no real collision, i.e the "Robin Hood" case)

    a, b, evaluations = start_1, start_2, 0
    
    if length_1 < length_2:
        a, b, length_1, length_2 = b, a, length_2, length_1
    for _ in range(length_1 - length_2):
        a = step(a)
        evaluations += 1
    if a == b:
        return None  #same walk so not collision
    while True:
        next_a, next_b = step(a), step(b)
        evaluations += 2
        if next_a == next_b:
            return a, b, evaluations
        a, b = next_a, next_b

#this fn is a generator that yields collisions forever 
#we can stop it w break
def distinguished_point_rho(step: StepFunction, workers: int = None,
                            dp_bits: int = None):
    workers = workers or os.cpu_count() or 1
    if dp_bits is None:
        dp_bits = default_dp_bits(8 * step.n_bytes)
    #we make the job size small enough so tht results come back often and so that we notice a collision soon after it happens), big enough so that process overhead stays small. Roughly 1/64 of the expected total work, split over cores.
    expected = expected_collision_work(8 * step.n_bytes)
    budget = int(min(1 << 18, max(4 << dp_bits, expected / (64 * workers))))

    landmarks = {}      
    evaluations = 0
    seen_pairs = set()  #to avoid reporting the same collision twice

    def handle(trails):
        nonlocal evaluations
        found = []
        for landmark, start, length in trails:
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

    #ifworkers == 1 - run everything in this process
    if workers == 1:
        while True:
            trails, wasted = _walk_trails(step, dp_bits, budget)
            evaluations += wasted
            for a, b in handle(trails):
                yield _result(step, a, b, evaluations, len(landmarks),
                              dp_bits=dp_bits, workers=1)

    #as each job finishes, check its landmarks and asap start a replacement job
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
        #when the caller stops the generator - kill remaining jobs.
        executor.shutdown(wait=False, cancel_futures=True)


def find_collision(n_bytes: int, workers: int = None, dp_bits: int = None) -> RhoResult:
    """Convenience wrapper: first collision for the plain truncated hash."""
    gen = distinguished_point_rho(StepFunction(n_bytes), workers, dp_bits)
    result = next(gen)
    gen.close()
    return result
