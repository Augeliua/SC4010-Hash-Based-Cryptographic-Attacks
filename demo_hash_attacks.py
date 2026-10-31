"""Live demos for the hash-collision half. Run from the repository root:

    python demo_hash_attacks.py            # all four demos
    python demo_hash_attacks.py meaningful # just one: collision | meaningful | multi | extension

Every signature step uses signatures/lamport.py unchanged.
"""
import os
import sys
import time
from hashlib import sha256

from hash_attacks.common import expected_collision_work, lamport_hash
from hash_attacks.length_extension import NaiveServer, attack_unknown_key_length
from hash_attacks.meaningful_collision import find_meaningful_collision
from hash_attacks.multi_target import crack_public_key, forged_private_key
from hash_attacks.pollards_rho import find_collision
from signatures.lamport import generate_keypair, sign, verify


def banner(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


def demo_collision(n_bytes=6):
    banner(f"1. Pollard's rho: collision on SHA-256 truncated to {8 * n_bytes} bits")
    start = time.perf_counter()
    r = find_collision(n_bytes)
    print(f"Message A: {r.message_a.hex()}")
    print(f"Message B: {r.message_b.hex()}")
    print(f"Both hash to: {r.digest.hex()}")
    print(f"Hash evaluations: {r.hash_evaluations:,}  "
          f"(birthday bound ~{expected_collision_work(8 * n_bytes):,.0f}, "
          f"brute force would be ~{2 ** (8 * n_bytes):,})")
    print(f"Landmarks stored: {r.stored_points:,}  |  Time: {time.perf_counter() - start:.1f}s")


def demo_meaningful(n_bytes=5):
    banner(f"2. Meaningful collision forges a Lamport signature ({8 * n_bytes}-bit hash)")
    start = time.perf_counter()
    cheap, expensive, r, tried = find_meaningful_collision(n_bytes)
    h = lamport_hash(n_bytes)
    print(f"Found after {r.hash_evaluations:,} hash evaluations, "
          f"{tried} collision(s), {time.perf_counter() - start:.1f}s\n")
    print("--- Contract Alice signs ---\n" + cheap.decode())
    print("\n--- Attacker's contract ---\n" + expensive.decode())
    print(f"\nTruncated hashes: {h(cheap).hex()} vs {h(expensive).hex()}")
    private, public = generate_keypair(h)
    signature = sign(cheap, private, h)
    print("\nAlice signs the $10 contract.")
    print("Signature valid on $10 contract:    ", verify(cheap, signature, public, h))
    print("SAME signature valid on $10,000 one:", verify(expensive, signature, public, h))
    print("Do they collide under full SHA-256? ",
          sha256(cheap).digest() == sha256(expensive).digest())


def demo_multi(n_bytes=2):
    banner(f"3. Multi-target attack: Lamport key stolen from its public key ({8 * n_bytes}-bit hash)")
    h = lamport_hash(n_bytes)
    _, public = generate_keypair(h)
    start = time.perf_counter()
    r = crack_public_key(public, n_bytes)
    print(f"Public fingerprints (targets): {r.total_targets}")
    print(f"First secret fell after {r.first_hit_after:,} guesses "
          f"(one target alone: ~{2 ** (8 * n_bytes):,})")
    print(f"ALL {r.total_targets} secrets recovered after {r.guesses:,} guesses, "
          f"{time.perf_counter() - start:.1f}s, without seeing a single signature")
    key = forged_private_key(r, len(public.hashes))
    message = b"Alice transfers all her savings to Mallory"
    print(f"Forged message: {message.decode()}")
    print("Bob accepts forged signature:", verify(message, sign(message, key, h), public, h))


def demo_extension():
    banner("4. Length extension on FULL SHA-256: tag = SHA-256(key || message)")
    server = NaiveServer(os.urandom(23))
    message = b"user=raashi&role=student"
    tag = server.tag(message)
    print(f"Attacker sees:  {message!r}\n        tag:    {tag.hex()}")
    key_length, forged, forged_tag = attack_unknown_key_length(
        server, message, tag, b"&role=admin")
    print(f"Guessed key length: {key_length} bytes")
    print(f"Forged message: {forged!r}")
    print(f"Forged tag:     {forged_tag.hex()}")
    print("Server accepts forged message:", server.accepts(forged, forged_tag))


DEMOS = {"collision": demo_collision, "meaningful": demo_meaningful,
         "multi": demo_multi, "extension": demo_extension}

if __name__ == "__main__":
    chosen = sys.argv[1:] or list(DEMOS)
    for name in chosen:
        DEMOS[name]()
