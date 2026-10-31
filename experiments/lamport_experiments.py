"""Milestone 3: measure what happens when Alice reuses a Lamport signing key.

Run from the GitHub repository root:
    python -m experiments.lamport_experiments

Only uses Python's standard library. The random seed controls test messages;
real private secrets still come from the secure RNG inside generate_keypair().
"""

import csv
import random
import statistics
import time
from functools import partial
from pathlib import Path

from attacks.lamport_reuse import collect_exposed, exposed_count, forge_for_message
from signatures.lamport import generate_keypair, sha256_truncated, sign, verify

# Each row studies a different number of messages signed with ONE reused key.
OBSERVED_COUNTS = (1, 2, 4, 5, 8)
# 2 and 4 bytes are intentionally weak toy hashes; 32 is full SHA-256.
HASH_BYTES = (2, 4, 32)
TRIALS = 60
SEARCH_LIMIT = 500
SEED = 4010
OUTPUT_DIR = Path('experiments') / 'results'


def trial(hash_bytes, observed_count, rng):
    """Run one independent reuse attack and return its measurements."""
    hash_fn = partial(sha256_truncated, digest_bytes=hash_bytes)
    private, public = generate_keypair(hash_fn)

    # Random-looking, reproducible messages; NOT predictable private keys.
    signed_messages = [
        f'Alice payment {rng.getrandbits(96)} #{i}'.encode()
        for i in range(observed_count)
    ]
    observations = [(msg, sign(msg, private, hash_fn)) for msg in signed_messages]

    # Start the stopwatch AFTER legitimate key generation and signing.
    # We measure the attacker's work, not Alice's legitimate work.
    started = time.perf_counter()
    exposed = collect_exposed(observations, hash_fn)
    disclosed = exposed_count(exposed)

    # FIXED-TARGET attack: the target is chosen BEFORE checking if it can
    # be signed. We allow only this one target (no searching for an easier one).
    target = f'Unapproved transfer {rng.getrandbits(96)}'.encode()
    fixed_signature = forge_for_message(target, exposed, hash_fn)
    fixed_ok = fixed_signature is not None and verify(target, fixed_signature, public, hash_fn)

    # EXISTENTIAL attack: attacker may try many different messages and keep
    # the first message for which all required secrets have been disclosed.
    # A message Alice actually signed is excluded (no replay counts as forgery).
    signed_set = set(signed_messages)
    forged = False
    attempts = 0
    for attempt in range(SEARCH_LIMIT):
        candidate = f'Attacker chosen {rng.getrandbits(96)} #{attempt}'.encode()
        attempts += 1
        if candidate in signed_set:
            continue
        fake_signature = forge_for_message(candidate, exposed, hash_fn)
        if fake_signature is not None and verify(candidate, fake_signature, public, hash_fn):
            forged = True
            break

    attack_ms = (time.perf_counter() - started) * 1000
    return {
        'hash_bits': hash_bytes * 8,
        'observed_signatures': observed_count,
        'exposed_secrets': disclosed,
        'total_secrets': hash_bytes * 8 * 2,
        'fixed_target_success': int(fixed_ok),
        'existential_success': int(forged),
        'search_attempts': attempts,
        'attack_ms': round(attack_ms, 4),
    }


def run(trials=TRIALS, seed=SEED):
    """Aggregate repeated trials into CSV files and a console summary."""
    rng = random.Random(seed)  # Reproducible experiment messages only.
    raw = []
    summary = []
    for hash_bytes in HASH_BYTES:
        for k in OBSERVED_COUNTS:
            rows = [trial(hash_bytes, k, rng) for _ in range(trials)]
            raw.extend(rows)

            n = hash_bytes * 8
            # For k independent uniformly random hashes, the probability
            # of having the secret needed at ONE bit position is 1 - 2^(-k).
            # A fixed target needs this to happen at ALL n positions.
            predicted_fixed = (1 - 2 ** (-k)) ** n
            summary.append({
                'hash_bits': n,
                'observed_signatures': k,
                'trials': trials,
                'mean_exposed': round(statistics.mean(r['exposed_secrets'] for r in rows), 2),
                'total_secrets': 2 * n,
                'fixed_target_success_rate': round(statistics.mean(r['fixed_target_success'] for r in rows), 4),
                'theoretical_fixed_target_rate': round(predicted_fixed, 8),
                'existential_success_rate': round(statistics.mean(r['existential_success'] for r in rows), 4),
                'mean_attempts_including_failures': round(statistics.mean(r['search_attempts'] for r in rows), 1),
                'mean_attack_ms': round(statistics.mean(r['attack_ms'] for r in rows), 3),
            })
            print(f'{n:>3} bits | {k} signatures | '
                  f'exposed {summary[-1]["mean_exposed"]:>6}/{2*n} | '
                  f'fixed {summary[-1]["fixed_target_success_rate"]:.1%} | '
                  f'search {summary[-1]["existential_success_rate"]:.1%} | '
                  f'{summary[-1]["mean_attack_ms"]:.2f} ms')

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, rows in [('lamport_trials.csv', raw), ('lamport_summary.csv', summary)]:
        with (OUTPUT_DIR / name).open('w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print('\nSaved CSV results to:', OUTPUT_DIR.resolve())
    print('NOTE: zero successes in finite trials does not mean zero probability.')
    return summary


if __name__ == '__main__':
    run()
