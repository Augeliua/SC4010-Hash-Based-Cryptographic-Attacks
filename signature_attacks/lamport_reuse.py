"""Demonstrate Lamport one-time-key reuse using only Alice's observed signatures.

This is an educational attack. The attacker does NOT have Alice's private key.
For a fast demo, the companion script uses a deliberately weak 16-bit hash.
"""
from signatures.lamport import message_bits, verify


def collect_exposed(observations, hash_fn):
    """Gather the secret values Alice leaked in her legitimate signatures."""
    # Each observation is (message, signature). We know both because signatures
    # and their messages can be publicly visible; we never read Alice's key.
    exposed = None
    for message, signature in observations:
        # Hash Alice's message and split the digest into 0/1 bits. These bits
        # tell us which secret she revealed at each position.
        bits = message_bits(message, hash_fn)
        if len(bits) != len(signature):
            raise ValueError("Signature length is incompatible with the hash")

        # Make one dictionary per hash-bit position. For example, exposed[3]
        # may eventually contain {0: secret_for_0, 1: secret_for_1}.
        # With a 16-bit toy hash, this creates 16 dictionaries.
        if exposed is None:
            exposed = [dict() for _ in bits]
        if len(exposed) != len(bits):
            raise ValueError("Inconsistent hash lengths")

        # Store the secret Alice revealed for this particular position and bit.
        # If she reuses her key on another message with the opposite bit here,
        # we'll learn the other secret too. Repeated values simply overwrite
        # the same entry with an identical secret.
        for i, bit in enumerate(bits):
            exposed[i][bit] = signature[i]

    if exposed is None:
        raise ValueError("Need at least one observed signature")
    return exposed


def forge_for_message(target, exposed, hash_fn):
    """Try signing one target message using only secrets we've already seen."""
    # Just like Alice's signer, we first need the target message's hash bits.
    bits = message_bits(target, hash_fn)
    if len(bits) != len(exposed):
        raise ValueError("Target hash length differs from observations")

    # Check EVERY position: if the target needs a 0-secret but we've only
    # observed the 1-secret there (or vice versa), we cannot forge this target.
    # None means "not forgeable with the secrets collected so far".
    if any(bit not in exposed[i] for i, bit in enumerate(bits)):
        return None

    # Every required secret is available! Assemble a Lamport signature by
    # selecting one leaked secret per bit. Alice normally selects these from
    # her private key; we select them from our collected observations instead.
    return tuple(exposed[i][bit] for i, bit in enumerate(bits))


def find_forgery(exposed, hash_fn, signed_messages, max_attempts=100000):
    """Search for SOME new message we can forge (existential forgery)."""
    # Track Alice's original messages so we don't accidentally count a replay
    # of one of her real signatures as a successful forgery.
    signed = set(signed_messages)
    for attempt in range(max_attempts):
        # Generate different candidate messages. encode() turns text into bytes
        # because our SHA-256 helper expects bytes.
        candidate = f"Unauthorized transaction #{attempt}".encode()
        if candidate in signed:
            continue

        # Try constructing a signature with the secrets we already collected.
        # A failed attempt does NOT reveal any new secrets; we just try a new
        # candidate whose hash may fit our available secret choices better.
        signature = forge_for_message(candidate, exposed, hash_fn)
        if signature is not None:
            # Return the new message, forged signature, and number of candidates
            # tried. The demo later asks Bob's verifier whether it accepts it.
            return candidate, signature, attempt + 1

    # Not finding one within our search limit doesn't prove forgery impossible.
    return None


def exposed_count(exposed):
    # Count how many DISTINCT secrets have been revealed in total.
    # Each bit position contributes either 1 (one bit value seen) or 2
    # (both 0 and 1 seen). For a 16-bit toy hash, the maximum is 32.
    return sum(len(choices) for choices in exposed)
