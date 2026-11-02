#sooo tis attack finds a collision between the 2 contracts A n B  
#signatures sign the hash, hence Alice's signature on A also verifies on B.

#one template yields 2^(n-1) distinct versions of each unique contract, all meaning the same thing. 

from hash_attacks.pollards_rho import StepFunction, distinguished_point_rho

AMOUNTS = ("$10", "$10,000")

#the template is a list of pieces
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

#vv normal-looking closing paragraph. After each word we add a choice point - single space or double space.
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

#for speed
def _build_byte_tables():
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
            text, bit = [], 7  #msb wld be the first choice point
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
MAX_BYTES = len(_TABLES)  #the largest hash size 

#turning an n-byte value into 1 specific ver of the contract
def render_contract(x: bytes) -> bytes:
    n = len(x)
    if n > MAX_BYTES:
        raise ValueError("not enough variation points for this hash size")
    #different x hence different text.
    return (b"".join(_TABLES[j][x[j]] for j in range(n))
            + b"".join(table[0] for table in _TABLES[n:]) + _TAIL)


def contract_amount(message: bytes) -> str:
    return AMOUNTS[1] if AMOUNTS[1].encode() in message else AMOUNTS[0]


def find_meaningful_collision(n_bytes: int, workers: int = None):
    #so return (cheap_contract, expensive_contract, rho_result, collisions_tried)
    step = StepFunction(n_bytes, encoder=render_contract)
    tried = 0
    generator = distinguished_point_rho(step, workers)
    try:
        for result in generator:
            tried += 1
            amounts = {contract_amount(result.message_a): result.message_a,
                       contract_amount(result.message_b): result.message_b}
            if len(amounts) == 2:  #success!!
                return amounts[AMOUNTS[0]], amounts[AMOUNTS[1]], result, tried
            #both versions have the same amount;; keep searching.
    finally:
        generator.close()
