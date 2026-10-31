"""Rollback exploit: reuse a WOTS+ leaf key, then FORGE a new XMSS message."""
from dataclasses import dataclass
from attacks.wots_attacks import search_key_reuse
from signatures.xmss import XMSSSigner, XMSSSignature, verify


@dataclass(frozen=True)
class RollbackResult:
    observed_count: int
    reused_index: int
    forged: XMSSSignature
    forged_message: bytes
    attempts: int


def perform_rollback_attack(signer: XMSSSigner, observations: int = 12,
                            max_attempts: int = 100_000) -> RollbackResult:
    """Simulate a server that repeatedly loads an out-of-date state backup."""
    if observations < 2:
        raise ValueError('Need >=2 signatures to illustrate reuse')
    saved = signer.snapshot_state()  # The old backup says 'next index is 0'.
    recorded = []
    for i in range(observations):
        signer.restore_state_unchecked(saved)  # VULNERABILITY: index goes backwards.
        msg = f'Legitimate server approval #{i}'.encode()
        sig = signer.sign(msg)
        # These signatures must all come from the same one-time leaf.
        assert sig.index == saved
        assert verify(msg, sig, signer.public)
        recorded.append((msg, sig))

    # Extract only the publicly observed WOTS+ portions (not private keys).
    wots_observations = [(msg, sig.wots_signature) for msg, sig in recorded]
    leaf_pub = recorded[0][1].wots_public
    found = search_key_reuse(wots_observations, leaf_pub, max_attempts)
    if found is None:
        raise RuntimeError('No forgery within search limit; rerun or raise limit')

    # The attacker keeps the *auth path* and *leaf index* from a real signature,
    # but replaces the WOTS+ signature with their forged one. SAME ROOT!
    source = recorded[0][1]
    forged = XMSSSignature(saved, found.signature, leaf_pub, source.auth_path)
    assert found.message not in {msg for msg, _ in recorded}
    assert verify(found.message, forged, signer.public)
    return RollbackResult(observations, saved, forged, found.message, found.attempts)
