# hash_attacks/ (hash-collision half)

Run everything from the repository root.

| File | What it does |
|---|---|
| `common.py` | Truncated SHA-256, identical to `signatures/lamport.py`'s toy hash |
| `birthday.py` | Birthday attack with a lookup table (fast, but memory ~2^(n/2)) |
| `pollards_rho.py` | Floyd rho (no memory) and parallel distinguished-point rho |
| `meaningful_collision.py` | $10 vs $10,000 contracts with the same hash (Yuval's attack) |
| `multi_target.py` | Recovers a whole Lamport private key from its public key |
| `length_extension.py` | Forges SHA-256(key ‖ message) tags on full SHA-256 |
| `run_experiments.py` | Runs all measurements, saves CSVs and graphs to `results/` |

```
python -m unittest -v                          # all tests (both halves)
python demo_hash_attacks.py                    # live demos
python -m hash_attacks.run_experiments         # quick experiments + graphs
python -m hash_attacks.run_experiments --full  # adds 56-bit rho, 24-bit multi-target
```
