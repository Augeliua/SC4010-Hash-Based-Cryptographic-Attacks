"""Run from project root: python demo_xmss_rollback.py"""
from signatures.xmss import XMSSSigner, verify
from attacks.xmss_rollback import perform_rollback_attack

# 2-byte WOTS+ hashes deliberately weaken the demo for fast attacks.
# Tree hashes remain SHA-256. 2**4 = 16 distinct WOTS+ keys available.
signer = XMSSSigner(height=4, n=2)
root = signer.public.root
print('=== NORMAL XMSS-STYLE SIGNING ===')
first = signer.sign(b'Approval A')
second = signer.sign(b'Approval B')
print('Signing indices:', first.index, second.index)
print('Valid signatures:', verify(b'Approval A', first, signer.public),
      verify(b'Approval B', second, signer.public))
print('Tampered message accepted:', verify(b'TAMPERED', first, signer.public))
print('Root stays the same:', signer.public.root == root)

print('\n=== STALE BACKUP / STATE ROLLBACK ATTACK ===')
# A separate signer models another server restored to an earlier state.
victim = XMSSSigner(height=4, n=2)
result = perform_rollback_attack(victim, observations=12)
print('Observed legitimate signatures:', result.observed_count)
print('Reused WOTS+ leaf index:', result.reused_index)
print('Forged message:', result.forged_message.decode())
print('Candidate messages checked:', result.attempts)
print('XMSS-style root verifier accepts forgery:',
      verify(result.forged_message, result.forged, victim.public))
print('Merkle authentication path length:', len(result.forged.auth_path))
