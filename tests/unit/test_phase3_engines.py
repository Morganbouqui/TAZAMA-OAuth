import pytest,httpx
from tazama_oauth.testing.models import TestMutation,MutationKind
from tazama_oauth.testing.mutation import mutate_url
from tazama_oauth.testing.baseline import create_baseline
from tazama_oauth.testing.differential import compare
from tazama_oauth.testing.confidence import classify
from tazama_oauth.core.models import EvidenceState
from tazama_oauth.http.models import HTTPResult
from tazama_oauth.evidence.models import RedirectHop

def test_mutations_centralized():
 m=TestMutation('state','state',MutationKind.REMOVE_PARAMETER,'https://app.test/a?state=x&client_id=c','binding','b'); assert 'state=' not in mutate_url(m.target,m)
 m.mutation=MutationKind.EMPTY_PARAMETER; assert 'state=' in mutate_url(m.target,m)
 m.mutation=MutationKind.REPLACE_PARAMETER; m.replacement='y'; assert 'state=y' in mutate_url(m.target,m)
 m.mutation=MutationKind.DUPLICATE_PARAMETER; assert mutate_url(m.target,m).count('state=')==2

def test_differential_deterministic():
 r1=HTTPResult('https://app.test/a',302,{'location':'https://app.test/cb?error=access_denied'},'abc',[RedirectHop('https://app.test/a',302,'https://app.test/cb?error=access_denied',True,True)])
 b=create_baseline('GET','https://app.test/a?state=SECRET',{},None,r1,'e1')
 r2=HTTPResult('https://app.test/a',400,{},'abcd',[])
 d=compare(b,r2); assert d.status_changed and d.location_changed and d.redirect_chain_changed and d.body_hash_changed and d.body_length_delta==1
 assert 'SECRET' not in str(b.as_dict())

def test_confidence_transitions():
 assert classify(observed=True)==EvidenceState.OBSERVED
 assert classify(suspicious_acceptance=True)==EvidenceState.POTENTIAL
 assert classify(rejected=True)==EvidenceState.NOT_REPRODUCED
 assert classify(reproduced_consequence=True)==EvidenceState.CONFIRMED
