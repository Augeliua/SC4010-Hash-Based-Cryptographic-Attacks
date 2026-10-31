"""Draw a presentation-ready graph from YOUR actual Milestone 3 CSV.

Run from project root:
    python -m integration.plot_lamport_results

Install matplotlib only if needed: python -m pip install matplotlib
"""
import csv
from pathlib import Path

INPUT = Path('experiments/results/lamport_summary.csv')
OUTPUT = Path('experiments/results/lamport_256bit.png')


def run():
    # Never hardcode the previous run's percentages into a chart.
    # Our graph should always reflect the measurements on YOUR computer.
    if not INPUT.exists():
        raise SystemExit('Run python -m experiments.lamport_experiments first.')
    with INPUT.open(newline='', encoding='utf-8') as f:
        rows = [r for r in csv.DictReader(f) if int(r['hash_bits']) == 256]
    rows.sort(key=lambda r: int(r['observed_signatures']))
    if not rows:
        raise SystemExit('No 256-bit results in the CSV.')
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit('Install plotting support: python -m pip install matplotlib') from exc

    x = [int(r['observed_signatures']) for r in rows]
    fixed = [100 * float(r['fixed_target_success_rate']) for r in rows]
    searched = [100 * float(r['existential_success_rate']) for r in rows]
    theoretical = [100 * float(r['theoretical_fixed_target_rate']) for r in rows]

    plt.figure(figsize=(8, 4.6))
    plt.plot(x, fixed, 'o-', label='Fixed target (measured)')
    plt.plot(x, searched, 's-', label='Attacker-selected, ≤500 tries (measured)')
    plt.plot(x, theoretical, '--', label='Fixed target (theory)')
    plt.xlabel('Number of signatures observed using the SAME key')
    plt.ylabel('Successful trials (%)')
    plt.title('Lamport key reuse — SHA-256, 256-bit digest')
    plt.ylim(-3, 103)
    plt.xticks(x)
    plt.grid(alpha=0.25)
    plt.legend(fontsize=8)
    plt.tight_layout()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTPUT, dpi=180)
    plt.close()
    print(f'Chart saved to {OUTPUT}')


if __name__ == '__main__':
    run()
