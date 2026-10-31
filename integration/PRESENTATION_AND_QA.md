# SC4010 — final presentation and Q&A guide

## A. Eight-minute group presentation (suggested timing)

**Important:** You and Raashi share *one* 8-minute slot. Proposed time split: signature forgery 4 min 20 s, hash attacks 3 min, introduction/conclusion 40 s. Adjust after timing the actual demos.

| Time | Slide | Speaker | What to show/say |
|---|---|---|---|
| 0:00–0:30 | 1. Security question | Both | What fails when cryptographic assumptions are violated? Separate hash weaknesses from signing-key misuse. |
| 0:30–1:05 | 2. Lamport basics | You | Two secrets per digest bit; one revealed in each signature; never reuse one-time keys. |
| 1:05–2:00 | 3. Lamport forgery + experiment | You | Demo the forged message. Show **measured** 256-bit graph, distinguish fixed-target vs attacker-selected attacks. |
| 2:00–2:45 | 4. WOTS+ | You | Hash-chain value at position d, verifier continues to 15. Checksum reverses the direction of desired message-only changes. |
| 2:45–3:40 | 5. WOTS+ attacks | You | Removing checksum enables forward-chain forgery; reusing keys leaks lower chain positions, including checksum positions. |
| 3:40–4:50 | 6. XMSS rollback | You | Merkle root authenticates many WOTS+ keys, but rollback reuses one leaf, enabling verified forgery. |
| 4:50–6:50 | 7. Hash attacks | Raashi | Insert Raashi's *actual* collision, Pollard rho and multi-target results here. Show parameters, attempts and validation. |
| 6:50–7:35 | 8. Connection | Both | A collision in the **exact digest that is signed** may allow signature transfer to a different message; do not claim an arbitrary hash collision breaks every signature design. State chosen-message and hash-domain assumptions. |
| 7:35–8:00 | 9. Conclusions | Both | Key reuse and rollback threaten stateful hash-based signatures; robust digest choices and state management are essential. |

## B. Live demo commands (Windows PowerShell, project root)

```powershell
python -m integration.final_check
python -m experiments.lamport_experiments
python -m integration.plot_lamport_results
```

If time is tight, run individual demos instead of every automatic test:

```powershell
python demo_lamport_forgery.py
python demo_wots_attacks.py
python demo_xmss_rollback.py
```

**Before presenting:** inspect the printed output; capture a screenshot of the *actual* working output as a fallback. Do not rely solely on a live run succeeding during an 8-minute talk.

## C. How to describe each result without overclaiming

- **Lamport:** 256-bit message digest experiments measure leakage from repeated signing, not SHA-256 collision resistance. The toy 16-bit hash also has independently weak collision and preimage security.
- **WOTS+:** Both attacks use our deliberately simplified WOTS+-style code and toy `n=2` parameters. Checksum-removal breaks our *intentionally weakened* variant; key reuse also breaks the checksum-protected toy variant. Neither is a claim of breaking correctly operated standard WOTS+.
- **XMSS:** This is an **XMSS-style** tree, not RFC-conformant XMSS. The rollback demonstration repeats index reuse to produce a forgery. A single rollback does not guarantee an instant forgery.
- **Measured rates:** 60 independent trials per setting; the attacker-selected search is capped at 500 candidates. A 0% observation means zero successes in that finite sample, not impossible in general.
- **Timings:** Measured runtime is machine dependent; note whether collection and failed candidate searches are included (they are, in our Lamport experiment).
- **Reproducibility:** Seed 4010 controls message selection; signing secrets use a cryptographically secure RNG. The CSV rates should replicate for a given code/seed; timings differ across machines.

## D. Likely professor Q&A (short defensible answers)

**Q: Are you breaking SHA-256?** No. We exploit one-time-key reuse and deliberately weakened toy designs. Truncating SHA-256 is for practical demonstrations, not evidence of a full SHA-256 break.

**Q: Why 512 Lamport private secrets?** A 256-bit message digest has 256 positions and each needs a 0-secret and a 1-secret, so 512 secrets. One signature reveals 256.

**Q: Why can WOTS+ signatures be extended?** Revealed hash-chain values can be advanced with public information but not normally reversed. The checksum ensures a message-digit increase induces a checksum decrease, blocking straightforward single-signature extension.

**Q: Is the checksum enough if keys are reused?** No. Reuse can reveal multiple positions for the same message and checksum chains, and an attacker can start from the lowest observed position in each chain.

**Q: Why does the XMSS Merkle tree not prevent index reuse?** The Merkle path proves that a WOTS+ public key is one of the committed leaves; it does not prove that its private key was only used once. That requires state management.

**Q: Is the forged message targeted?** In our demonstrations the attacker searches for a suitable new message. That's existential forgery; a specific fixed target is generally harder.

**Q: How would you defend against rollback?** Atomically persist the advanced signing index, protect backups from restoring earlier key usage, and use monotonic hardware-backed counters or equivalent rollback-resistant state controls where practical.

**Q: Can Raashi's collision be used to forge your signatures?** Only when the collision is for the *exact message digest* the signature scheme uses (same domain separation, public seed/context and preprocessing), with a valid signed member of the colliding pair. Then the same signature may verify on the other message. An unrelated truncated-SHA collision isn't automatically an XMSS forgery.

## E. Final checks for repository

- No `__pycache__`, `.pyc`, temporary secrets, or private signing keys committed.
- Include README with prerequisites, execution commands and toy/real security caveat.
- Run `python -m unittest discover -s tests -v` and the integrated checker.
- Save demo output and Lamport CSV/graph; label measured and theoretical lines clearly.
- Ask Raashi to add measured hash-attack results before making combined claims.
