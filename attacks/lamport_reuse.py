"""Educational Lamport OTS key-reuse attack using only observed signatures."""
from signatures.lamport import message_bits, verify


def collect_exposed(observations, hash_fn):
    """observations: iterable of (message_bytes, signature_tuple)."""
    exposed = None
    for message, signature in observations:
        bits = message_bits(message, hash_fn)
        if len(bits) != len(signature):
            raise ValueError("Signature length is incompatible with the hash")
        if exposed is None:
            exposed = [dict() for _ in bits]
        if len(exposed) != len(bits):
            raise ValueError("Inconsistent hash lengths")
        for i, bit in enumerate(bits):
            exposed[i][bit] = signature[i]
    if exposed is None:
        raise ValueError("Need at least one observed signature")
    return exposed


def forge_for_message(target, exposed, hash_fn):
    """Return a signature for target iff all needed secret choices were observed."""
    bits = message_bits(target, hash_fn)
    if len(bits) != len(exposed):
        raise ValueError("Target hash length differs from observations")
    if any(bit not in exposed[i] for i, bit in enumerate(bits)):
        return None
    return tuple(exposed[i][bit] for i, bit in enumerate(bits))


def find_forgery(exposed, hash_fn, signed_messages, max_attempts=100000):
    """Search for a fresh message with a forgeable digest. Never accesses the key."""
    signed = set(signed_messages)
    for attempt in range(max_attempts):
        candidate = f"Unauthorized transaction #{attempt}".encode()
        if candidate in signed:
            continue
        signature = forge_for_message(candidate, exposed, hash_fn)
        if signature is not None:
            return candidate, signature, attempt + 1
    return None


def exposed_count(exposed):
    return sum(len(choices) for choices in exposed)
