"""Run with: python demo_wots_plus.py"""
from signatures.wots_plus import (
    base16_digits, checksum_digits, generate_keypair, lengths,
    sign, signing_digits, verify,
)

n = 32
private, public = generate_keypair(n)
message = b'Pay Bob $10'
signature = sign(message, private)
len1, len2 = lengths(n)
digits = signing_digits(message, n)

print('WOTS+-style educational demonstration')
print(f'Message digits: {len1}; checksum digits: {len2}')
print(f'Total hash chains/signature elements: {len(digits)}')
print(f'Signature bytes: {sum(len(x) for x in signature)}')
print('Valid signature accepted:', verify(message, signature, public))
print('Modified message accepted:', verify(b'Pay Bob $100', signature, public))
print('First 8 message digits:', base16_digits(message, n)[:8])
print('Checksum digits:', checksum_digits(base16_digits(message, n), len2))
