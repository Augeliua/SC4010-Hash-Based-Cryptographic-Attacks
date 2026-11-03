# implementing WOTS+ misuse attacks, build on signatures/wots_plus.py
# Attack 1 intentionally removes the checksum
# Attack 2 reuses a key in our checksum-protected WOTS+-style implementation
from dataclasses import dataclass
from signatures.wots_plus import (W, chain, base16_digits, signing_digits,
                                  WOTSPublicKey, WOTSPrivateKey)

# attack 1

@dataclass(frozen=True)
class Forgery:
    message: bytes
    signature: tuple[bytes, ...]
    attempts: int


def sign_without_checksum(message: bytes, private: WOTSPrivateKey) -> tuple[bytes, ...]:
    # deliberately signs only the message digits, ignoring the checksum. this is an intentional misuse of WOTS+.
    digits = base16_digits(message, private.n)
    return tuple(chain(private.starts[i], 0, digit, i,
                       private.public_seed, private.n)
                 for i, digit in enumerate(digits))


def verify_without_checksum(message: bytes, signature: tuple[bytes, ...],
                            public: WOTSPublicKey) -> bool:
    # implements an intentionally weakened verifier that checks message chains but ignores checksum chain.
    digits = base16_digits(message, public.n)
    if len(signature) != len(digits) or any(len(x) != public.n for x in signature):
        return False
    for i, (node, digit) in enumerate(zip(signature, digits)):
        endpoint = chain(node, digit, W - 1 - digit, i,
                         public.public_seed, public.n)
        if endpoint != public.ends[i]:
            return False
    return True


def extend_signature(old_message: bytes, old_signature: tuple[bytes, ...],
                     new_message: bytes, public: WOTSPublicKey,
                     include_checksum: bool) -> tuple[bytes, ...] | None:
    # forge by moving forward along publicly computable hash chains.
    # for every chain, the target digit must be >= the observed digit.
    
    get_digits = signing_digits if include_checksum else base16_digits
    old = get_digits(old_message, public.n)
    new = get_digits(new_message, public.n)
    if len(old_signature) != len(old) or len(new) != len(old):
        raise ValueError('Signature and digit counts do not match')
    if any(after < before for before, after in zip(old, new)):
        return None
    return tuple(chain(node, before, after - before, i,
                       public.public_seed, public.n)
                 for i, (node, before, after) in enumerate(zip(old_signature, old, new)))


def search_checksum_removal(original: bytes, signature: tuple[bytes, ...],
                            public: WOTSPublicKey,
                            max_attempts: int = 100_000) -> Forgery | None:
    # generates candidtaes msgs, searching for one whose digits can all be reached by advancing the observed chains.
    for attempt in range(max_attempts):
        candidate = f'Attacker-selected document #{attempt}'.encode()
        if candidate == original:
            continue
        forged = extend_signature(original, signature, candidate, public, False)
        if forged is not None and verify_without_checksum(candidate, forged, public):
            return Forgery(candidate, forged, attempt + 1)
    return None

# attack 2

def collect_reused_positions(observations: list[tuple[bytes, tuple[bytes, ...]]],
                             public: WOTSPublicKey) -> list[tuple[int, bytes]]:
    # at each chain keep the lowest exposed position (earliest node).

    if not observations:
        raise ValueError('Need at least one observed signature')
    best: list[tuple[int, bytes]] = []
    for message, signature in observations:
        digits = signing_digits(message, public.n)  # includes checksum
        if len(signature) != len(public.ends):
            raise ValueError('Signature has incorrect chain count')
        if not best:
            best = list(zip(digits, signature))
        else:
            for i, (digit, node) in enumerate(zip(digits, signature)):
                if digit < best[i][0]:
                    best[i] = (digit, node)
    return best


def forge_from_reuse(target: bytes, positions: list[tuple[int, bytes]],
                     public: WOTSPublicKey) -> tuple[bytes, ...] | None:
    # check that every target digit can b reached by advancing a previously observed chain value. 
    # construct a forged signature by advancing a previously observed chain value.

    digits = signing_digits(target, public.n)
    if len(positions) != len(digits):
        raise ValueError('Observed chain positions have incorrect length')
    if any(target_digit < known_digit
           for target_digit, (known_digit, _) in zip(digits, positions)):
        return None
    return tuple(chain(node, old_digit, digit - old_digit, i,
                       public.public_seed, public.n)
                 for i, ((old_digit, node), digit) in enumerate(zip(positions, digits)))


def search_key_reuse(observations: list[tuple[bytes, tuple[bytes, ...]]],
                     public: WOTSPublicKey,
                     max_attempts: int = 100_000) -> Forgery | None:
    # search for any new message we can forge (existential forgery) by reusing a previously observed key.
    from signatures.wots_plus import verify
    signed = {message for message, _ in observations}
    best = collect_reused_positions(observations, public)
    for attempt in range(max_attempts):
        candidate = f'Reused-key forged message #{attempt}'.encode()
        if candidate in signed:
            continue
        forged = forge_from_reuse(candidate, best, public)
        if forged is not None and verify(candidate, forged, public):
            return Forgery(candidate, forged, attempt + 1)
    return None
