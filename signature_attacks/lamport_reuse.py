# demonstrate attack from reusing Lamport signatures
from signatures.lamport import message_bits, verify


def collect_exposed(observations, hash_fn):
    # gather the secret values Alice leaked in her signatures
    exposed = None
    for message, signature in observations:
        # hash Alice's msg and split the digest into 0/1 bits. these bits tell us which secret she revealed at each position.
        bits = message_bits(message, hash_fn)
        if len(bits) != len(signature):
            raise ValueError("Signature length is incompatible with the hash")

        # make one dictionary per hash-bit position -> with a 16-bit toy hash, this creates 16 dictionaries
        if exposed is None:
            exposed = [dict() for _ in bits]
        if len(exposed) != len(bits):
            raise ValueError("Inconsistent hash lengths")

        # store the secret Alice revealed for this particular position and bit.
        # if she reuses her key on another message with the opposite bit here, we'll learn the other secret too. 
        for i, bit in enumerate(bits):
            exposed[i][bit] = signature[i]

    if exposed is None:
        raise ValueError("Need at least one observed signature")
    return exposed


def forge_for_message(target, exposed, hash_fn):
    # try signing one target message using only secrets we've already seen
    bits = message_bits(target, hash_fn)
    if len(bits) != len(exposed):
        raise ValueError("Target hash length differs from observations")
.
    if any(bit not in exposed[i] for i, bit in enumerate(bits)):
        return None

    # here, every required secret is available. asssemble a Lamport signature by selecting one leaked secret per bit
    return tuple(exposed[i][bit] for i, bit in enumerate(bits))


def find_forgery(exposed, hash_fn, signed_messages, max_attempts=100000):
    # search for any new message we can forge (existential forgery)
    signed = set(signed_messages)
    for attempt in range(max_attempts):
        # generate different candidate messages and convert text into bytes (SHA-256 helper expects bytes)
        candidate = f"Unauthorized transaction #{attempt}".encode()
        if candidate in signed:
            continue

        # try constructing a signature with the secrets we already collected
        signature = forge_for_message(candidate, exposed, hash_fn)
        if signature is not None:
            # return the new message, forged signature, and number of candidates tried
            return candidate, signature, attempt + 1

    # note: not finding one within our search limit doesn't prove forgery impossible.
    return None


def exposed_count(exposed):
    # count how many distinct secrets have been revealed in total
    return sum(len(choices) for choices in exposed)
