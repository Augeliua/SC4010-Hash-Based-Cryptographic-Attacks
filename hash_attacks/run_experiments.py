"""Run every hash experiment, save CSVs, and draw the presentation graphs.

Run from the repository root:
    python -m hash_attacks.run_experiments            # quick (~1 to 3 minutes)
    python -m hash_attacks.run_experiments --full     # adds 56-bit rho and 24-bit multi-target
    python -m hash_attacks.run_experiments --full --big   # also 64-bit rho (leave running)

Outputs go to hash_attacks/results/.

WHY MANY TRIALS? A single collision search is very random: it can finish at
a third of the expected work or take three times as long. Averaging many
trials is what lets us compare our measurements against the theory lines.
"""
import argparse
import csv
import os
import statistics
import time
from pathlib import Path

from hash_attacks.birthday import birthday_attack
from hash_attacks.common import expected_collision_work
from hash_attacks.meaningful_collision import find_meaningful_collision
from hash_attacks.multi_target import guesses_until_first_hit
from hash_attacks.pollards_rho import StepFunction, find_collision, floyd_rho

RESULTS = Path(__file__).parent / "results"


def _save(name, rows):
    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / f"{name}.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def collision_experiments(full, big, workers):
    """Birthday vs Floyd rho vs distinguished-point rho vs meaningful collisions."""
    rows = []
    plan = [  # (method, n_bytes, trials)
        ("birthday", 2, 50), ("birthday", 3, 30), ("birthday", 4, 15), ("birthday", 5, 3),
        ("floyd_rho", 2, 50), ("floyd_rho", 3, 30), ("floyd_rho", 4, 10),
        ("dp_rho", 2, 50), ("dp_rho", 3, 30), ("dp_rho", 4, 15), ("dp_rho", 5, 5),
        ("dp_rho", 6, 3),
        ("meaningful", 3, 10), ("meaningful", 4, 5), ("meaningful", 5, 2),
    ]
    if full:
        plan += [("dp_rho", 7, 2), ("meaningful", 6, 1)]
    if big:
        plan += [("dp_rho", 8, 1)]

    for method, n_bytes, trials in plan:
        for trial in range(trials):
            if method == "birthday":
                r, secs = _timed(lambda: birthday_attack(n_bytes))
                work, memory = r.hashes_computed, r.table_size
            elif method == "floyd_rho":
                r, secs = _timed(lambda: floyd_rho(StepFunction(n_bytes)))
                work, memory = r.hash_evaluations, 0
            elif method == "dp_rho":
                r, secs = _timed(lambda: find_collision(n_bytes, workers))
                work, memory = r.hash_evaluations, r.stored_points
            else:
                (_, _, r, _), secs = _timed(lambda: find_meaningful_collision(n_bytes, workers))
                work, memory = r.hash_evaluations, r.stored_points
            rows.append({"method": method, "n_bits": 8 * n_bytes, "trial": trial,
                         "hash_evaluations": work, "stored_items": memory,
                         "seconds": round(secs, 3)})
            print(f"{method:>10} {8 * n_bytes:>2} bits  trial {trial + 1}/{trials}  "
                  f"work={work:>12,}  memory={memory:>9,}  {secs:7.2f}s")
    _save("collisions", rows)
    return rows


def multi_target_experiments(full):
    """Guesses until the first preimage, as the number of targets T grows."""
    rows = []
    plan = [(2, t, 200) for t in (1, 2, 4, 8, 16, 32)]
    if full:
        plan += [(3, t, 5) for t in (1, 8, 48)]
    for n_bytes, targets, trials in plan:
        for trial in range(trials):
            guesses = guesses_until_first_hit(targets, n_bytes)
            rows.append({"n_bits": 8 * n_bytes, "targets": targets,
                         "trial": trial, "guesses": guesses})
        mean = statistics.mean(r["guesses"] for r in rows[-trials:])
        print(f"multi-target {8 * n_bytes} bits  T={targets:>2}  mean guesses={mean:>12,.0f}"
              f"  theory={2 ** (8 * n_bytes) / targets:>12,.0f}")
    _save("multi_target", rows)
    return rows


def _means(rows, key, group_keys):
    groups = {}
    for row in rows:
        groups.setdefault(tuple(row[k] for k in group_keys), []).append(row[key])
    return {k: statistics.mean(v) for k, v in sorted(groups.items())}


def plot(collision_rows, multi_rows):
    import matplotlib
    matplotlib.use("Agg")  # draw straight to files, no window needed
    import matplotlib.pyplot as plt

    labels = {"birthday": "Birthday (table)", "floyd_rho": "Floyd rho",
              "dp_rho": "Distinguished-point rho", "meaningful": r"Meaningful (\$10 vs \$10,000)"}

    # Graph 1: work vs hash size, against the birthday bound.
    work = _means(collision_rows, "hash_evaluations", ("method", "n_bits"))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    all_bits = sorted({r["n_bits"] for r in collision_rows})
    ax.plot(all_bits, [expected_collision_work(n) for n in all_bits], "k--",
            label="Theory: 1.25 x 2^(n/2)")
    for method, label in labels.items():
        points = [(n, w) for (m, n), w in work.items() if m == method]
        if points:
            ax.plot(*zip(*points), "o-", label=label)
    ax.set_yscale("log", base=2)
    ax.set_xlabel("Hash size n (bits)")
    ax.set_ylabel("Hash evaluations (mean, log2 scale)")
    ax.set_title("Collision cost grows like 2^(n/2), not 2^n")
    ax.legend()
    fig.tight_layout()
    fig.savefig(RESULTS / "collision_work.png", dpi=200)

    # Graph 2: memory, birthday table vs rho landmarks.
    memory = _means(collision_rows, "stored_items", ("method", "n_bits"))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for method in ("birthday", "dp_rho"):
        points = [(n, max(m_, 1)) for (m, n), m_ in memory.items() if m == method]
        ax.plot(*zip(*points), "o-", label=labels[method])
    ax.set_yscale("log", base=2)
    ax.set_xlabel("Hash size n (bits)")
    ax.set_ylabel("Items stored (mean, log2 scale)")
    ax.set_title("Rho needs almost no memory (Floyd stores nothing)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(RESULTS / "collision_memory.png", dpi=200)

    # Graph 3: multi-target speedup.
    guesses = _means(multi_rows, "guesses", ("n_bits", "targets"))
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for n_bits in sorted({n for n, _ in guesses}):
        points = [(t, g) for (n, t), g in guesses.items() if n == n_bits]
        ts = [t for t, _ in points]
        ax.plot(*zip(*points), "o", label=f"Measured, {n_bits}-bit hash")
        ax.plot(ts, [2 ** n_bits / t for t in ts], "--", label=f"Theory 2^{n_bits} / T")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    ax.set_xlabel("Number of targets T")
    ax.set_ylabel("Guesses until first preimage (mean)")
    ax.set_title("More public fingerprints = proportionally easier attack")
    ax.legend()
    fig.tight_layout()
    fig.savefig(RESULTS / "multi_target.png", dpi=200)
    print(f"Graphs saved in {RESULTS}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="add slower, larger runs")
    parser.add_argument("--big", action="store_true", help="add a 64-bit rho run")
    parser.add_argument("--workers", type=int, default=os.cpu_count())
    args = parser.parse_args()
    collision_rows = collision_experiments(args.full, args.big, args.workers)
    multi_rows = multi_target_experiments(args.full)
    plot(collision_rows, multi_rows)


if __name__ == "__main__":
    main()
