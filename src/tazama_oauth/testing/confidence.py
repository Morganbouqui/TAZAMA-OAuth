from tazama_oauth.core.models import EvidenceState
def classify(*,observed=True,suspicious_acceptance=False,reproduced_consequence=False,rejected=False):
    if reproduced_consequence:return EvidenceState.CONFIRMED
    if suspicious_acceptance:return EvidenceState.POTENTIAL
    if rejected:return EvidenceState.NOT_REPRODUCED
    return EvidenceState.OBSERVED if observed else EvidenceState.POTENTIAL
