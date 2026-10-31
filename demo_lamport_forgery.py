"""Run from repository root: python demo_lamport_forgery.py"""
from functools import partial
from signatures.lamport import generate_keypair, sign, verify, sha256_truncated
from attacks.lamport_reuse import collect_exposed, find_forgery, exposed_count


def main():
    # TOY hash: SHA-256 truncated to 16 bits. Not secure or real-world parameters.
    toy_hash = partial(sha256_truncated, digest_bytes=2)
    private, public = generate_keypair(toy_hash)
    # Deliberate misuse: Alice signs multiple messages with ONE private key.
    signed_messages = [f"Authorized payment {i}".encode() for i in range(5)]
    observations = [(message, sign(message, private, toy_hash)) for message in signed_messages]
    assert all(verify(m, s, public, toy_hash) for m, s in observations)

    exposed = collect_exposed(observations, toy_hash)
    result = find_forgery(exposed, toy_hash, signed_messages)
    if result is None:
        print("No forged message found within search limit")
        return
    forged_message, forged_signature, attempts = result
    print("Observed legitimate signatures:", len(observations))
    print("Exposed secrets:", exposed_count(exposed), "of", 2 * len(exposed))
    print("Forgery message:", forged_message.decode())
    print("Attacker search attempts:", attempts)
    print("Message was never signed by Alice:", forged_message not in signed_messages)
    print("Bob accepts forged signature:", verify(forged_message, forged_signature, public, toy_hash))


if __name__ == "__main__":
    main()
