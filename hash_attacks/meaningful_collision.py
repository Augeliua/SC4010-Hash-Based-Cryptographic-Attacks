"""Meaningful collisions (Yuval's attack): two CONTRACTS with the same hash.

Random collisions (two blobs of junk bytes) don't hurt anyone. This attack
finds a collision between:
    contract A: Alice pays $10       (she happily signs this)
    contract B: Alice pays $10,000   (the attacker's version)
Signatures sign the HASH, so Alice's signature on A also verifies on B.

HOW WE GENERATE MANY VERSIONS OF A CONTRACT
Each n-byte value x is turned into a contract (render_contract). Every bit
of x controls one "choice point" in the template:
  * one choice point is the amount itself: $10 or $10,000
  * every other choice point is a tiny, harmless variation: a synonym
    ("pay" or "transfer") or a single vs double space after a word.
So one template yields 2^(n-1) distinct versions of EACH contract, all
meaning the same thing. Double spaces are nearly invisible on screen, which
is exactly why Yuval suggested them in 1979.

HOW WE FIND THE COLLISION
We plug render_contract into Pollard's rho: f(x) = H(render_contract(x)).
Rho finds x != y with H(render(x)) == H(render(y)). The amount bit of x and
y is effectively random, so about half of the collisions pair a $10 version
with a $10,000 version. When both got the same amount, we take the next one.
Expected cost: about 2 times the plain birthday bound.
"""
from hash_attacks.pollards_rho import StepFunction, distinguished_point_rho

AMOUNTS = ("$10", "$10,000")

# The template is a list of pieces. A plain string is fixed text. A tuple
# (option_0, option_1) is a choice point controlled by one bit of x.
_BODY = [
    ("Payment Agreement", "Payment Contract"), "\n\n",
    "I, Alice Tan, ", ("agree", "promise"), " to ", ("pay", "transfer"),
    " Bob Lee ", ("the sum of", "the amount of"), " ", AMOUNTS, " ",
    ("for", "in return for"), " ", ("consulting", "advisory"), " services ",
    ("delivered", "provided"), " in October 2026. ",
    "Payment ", ("will", "shall"), " be made by ", ("bank", "wire"),
    " transfer ", ("within", "no later than"), " ", ("thirty", "30"),
    " days of ", ("this agreement", "signing"), ". ",
    "This agreement is ", ("binding on", "binding upon"), " both parties and ",
    ("is governed by", "falls under"), " the laws of Singapore.\n\n",
]

# A normal-looking closing paragraph. After each word we add a choice point:
# single space or double space.
_FOOTER = (
    "Both parties confirm that they have read and understood every term of "
    "this agreement and sign it of their own free will. Two original copies "
    "will be kept, one by each party, for their records. Signed by Alice Tan "
    "and Bob Lee on 31 October 2026 in the presence of the witness Charlie Ng. "
    "Reference number PA-2026-117."
).split()


def _build_template():
    pieces = list(_BODY)
    for word in _FOOTER[:-1]:
        pieces += [word, (" ", "  ")]
    pieces.append(_FOOTER[-1])
    return pieces


TEMPLATE = _build_template()
CHOICE_POINTS = sum(isinstance(p, tuple) for p in TEMPLATE)
AMOUNT_CHOICE = [p for p in TEMPLATE if isinstance(p, tuple)].index(AMOUNTS)


def _build_byte_tables():
    """Speed trick: precompute text fragments one byte at a time.

    Split the template into segments containing 8 choice points each. For
    segment j there are only 256 possible texts (one per value of byte j),
    so we render all 256 once. Rendering a contract is then just
    "look up each byte's fragment and glue them together".
    """
    segments, current, choices = [], [], 0
    for piece in TEMPLATE:
        current.append(piece)
        if isinstance(piece, tuple):
            choices += 1
            if choices % 8 == 0:
                segments.append(current)
                current = []
    tail = "".join(p if isinstance(p, str) else p[0] for p in current)

    tables = []
    for segment in segments:
        table = []
        for byte in range(256):
            text, bit = [], 7  # most significant bit = first choice point
            for piece in segment:
                if isinstance(piece, tuple):
                    text.append(piece[(byte >> bit) & 1])
                    bit -= 1
                else:
                    text.append(piece)
            table.append("".join(text).encode())
        tables.append(table)
    return tables, tail.encode()


_TABLES, _TAIL = _build_byte_tables()
MAX_BYTES = len(_TABLES)  # largest hash size (in bytes) we can support


def render_contract(x: bytes) -> bytes:
    """Turn an n-byte value into one specific version of the contract."""
    n = len(x)
    if n > MAX_BYTES:
        raise ValueError("not enough variation points for this hash size")
    # Bytes of x choose fragments for the first n segments. Remaining segments
    # use byte 0 (every choice = option 0), so different x -> different text.
    return (b"".join(_TABLES[j][x[j]] for j in range(n))
            + b"".join(table[0] for table in _TABLES[n:]) + _TAIL)


def contract_amount(message: bytes) -> str:
    return AMOUNTS[1] if AMOUNTS[1].encode() in message else AMOUNTS[0]


def find_meaningful_collision(n_bytes: int, workers: int = None):
    """Return (cheap_contract, expensive_contract, rho_result, collisions_tried)."""
    step = StepFunction(n_bytes, encoder=render_contract)
    tried = 0
    generator = distinguished_point_rho(step, workers)
    try:
        for result in generator:
            tried += 1
            amounts = {contract_amount(result.message_a): result.message_a,
                       contract_amount(result.message_b): result.message_b}
            if len(amounts) == 2:  # one $10 and one $10,000: success
                return amounts[AMOUNTS[0]], amounts[AMOUNTS[1]], result, tried
            # Both versions have the same amount: harmless, keep searching.
    finally:
        generator.close()
