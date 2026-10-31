"""Run both WOTS+ attacks with practical toy parameters."""
from signatures.wots_plus import (generate_keypair, sign, verify,
                                  signing_digits, base16_digits)
from attacks.wots_attacks import (sign_without_checksum, verify_without_checksum,
    search_checksum_removal, extend_signature, collect_reused_positions,
    search_key_reuse)

# Two-byte digests make this live demonstration fast. We are NOT breaking SHA-256.
N = 2

print('=== ATTACK 1: CHECKSUM REMOVED (INTENTIONALLY BROKEN VARIANT) ===')
private, public = generate_keypair(n=N)
original = b'Alice approved the original document'
weak_sig = sign_without_checksum(original, private)
print('Original weak signature valid:', verify_without_checksum(original, weak_sig, public))
result = search_checksum_removal(original, weak_sig, public)
assert result is not None, 'Increase max_attempts if no suitable message is found'
print('Forged different message:', result.message.decode())
print('Candidate messages checked:', result.attempts)
print('Weak verifier accepts forgery:', verify_without_checksum(result.message, result.signature, public))
# In the protected scheme, the checksum goes down when the message digits go up.
# So you CANNOT simply extend every checksum chain forward from the old signature.
protected_sig = sign(original, private)
protected_extension = extend_signature(original, protected_sig, result.message,
                                       public, include_checksum=True)
print('Can extend checksum-protected signature the same way:', protected_extension is not None)

print('\n=== ATTACK 2: KEY REUSE WITH CHECKSUM STILL ENABLED ===')
private2, public2 = generate_keypair(n=N)
messages = [f'Alice signed document #{i}'.encode() for i in range(12)]
# Intentional mistake: reuse one key for ALL 12 messages.
observed = [(msg, sign(msg, private2)) for msg in messages]
positions = collect_reused_positions(observed, public2)
print('Observed legitimate signatures:', len(observed))
print('Chain positions exposed:', len(positions))
forgery = search_key_reuse(observed, public2)
assert forgery is not None, 'Increase max_attempts or number of observations'
print('Forged different message:', forgery.message.decode())
print('Candidate messages checked:', forgery.attempts)
print('Message was never signed by Alice:', forgery.message not in messages)
print('Full checksum-protected verifier accepts forgery:',
      verify(forgery.message, forgery.signature, public2))
