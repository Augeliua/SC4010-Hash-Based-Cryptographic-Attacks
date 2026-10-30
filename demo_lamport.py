from signatures.lamport import generate_keypair, sign, verify

private_key, public_key = generate_keypair()
original = b"Pay Bob $10"
modified = b"Pay Bob $100"
signature = sign(original, private_key)

print("Legitimate signature valid:", verify(original, signature, public_key))
print("Modified message accepted:", verify(modified, signature, public_key))
print("Signature elements:", len(signature))
print("Signature size (bytes):", sum(len(x) for x in signature))
