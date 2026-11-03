# implementing rollback exploit: reuse a WOTS+ leaf key, then forge a new XMSS message
from dataclasses import dataclass
from signature_attacks.wots_attacks import search_key_reuse
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
    # simulate a server that repeatedly loads an out-of-date state backup
    if observations < 2:
        raise ValueError('Need >=2 signatures to illustrate reuse')
    saved = signer.snapshot_state()  # records the next unused WOTS+ signing index
    recorded = []
    for i in range(observations):
        signer.restore_state_unchecked(saved)  # restores the same old index before each signing operation, deliberately causing key reuse
        msg = f'Legitimate server approval #{i}'.encode()
        sig = signer.sign(msg) # makes victim sign diff msgs using the same WOTS+ leaf (collect signatures)
        assert sig.index == saved # confirm key reuse 
        assert verify(msg, sig, signer.public)
        recorded.append((msg, sig))

    wots_observations = [(msg, sig.wots_signature) for msg, sig in recorded] # extract the observed WOTS+ signature wifout accessing their priv keys
    leaf_pub = recorded[0][1].wots_public
    found = search_key_reuse(wots_observations, leaf_pub, max_attempts) # reuse WOTS+ attack code to search for n construct a valid forged WOTS+ signature 
    if found is None:
        raise RuntimeError('No forgery within search limit; rerun or raise limit')

    source = recorded[0][1]
    forged = XMSSSignature(saved, found.signature, leaf_pub, source.auth_path) #combines the forged WOTS+ signature wif the ori leaf index, PK, n authentication path
    assert found.message not in {msg for msg, _ in recorded}
    assert verify(found.message, forged, signer.public) # cfm that the complete forged XMSS-style signature passes varification again ori merklet root
    return RollbackResult(observations, saved, forged, found.message, found.attempts)
