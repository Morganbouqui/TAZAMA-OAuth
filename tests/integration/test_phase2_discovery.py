import json,pytest,httpx
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.oauth.discovery.service import DiscoveryService

@pytest.mark.asyncio
async def test_passive_discovery_observes_authorization_request():
 html='<a href="https://app.test/authorize?client_id=c&response_type=code&scope=openid%20profile&state=s&nonce=n&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&code_challenge=x&code_challenge_method=S256">login</a>'
 async def h(req): return httpx.Response(200,text=html)
 p=ScopePolicy([ScopePolicy.parse_rule('app.test')]); d=await DiscoveryService(ControlledTransport(p,transport=httpx.MockTransport(h),rate_per_second=10000)).discover('https://app.test/')
 r=d['authorization_requests'][0]; assert r.state=='s' and r.nonce=='n' and r.scopes==['openid','profile'] and r.redirect_uri=='https://app.test/cb' and r.code_challenge_method=='S256'

@pytest.mark.asyncio
async def test_oidc_out_of_scope_endpoint_is_not_requested():
 seen=[]
 metadata={'issuer':'https://app.test','authorization_endpoint':'https://app.test/authorize','token_endpoint':'https://outside.test/token','jwks_uri':'https://app.test/jwks','userinfo_endpoint':'https://app.test/userinfo'}
 async def h(req): seen.append(str(req.url)); return httpx.Response(200,json=metadata)
 p=ScopePolicy([ScopePolicy.parse_rule('app.test')]); svc=DiscoveryService(ControlledTransport(p,transport=httpx.MockTransport(h),rate_per_second=10000)); m,e,_=await svc.oidc_discover('https://app.test/')
 assert len(seen)==1 and seen[0].endswith('/.well-known/openid-configuration'); token=[x for x in e if x.type=='token'][0]; assert token.scope_status=='OUT_OF_SCOPE' and token.request_status=='NOT_REQUESTED'

@pytest.mark.asyncio
async def test_phase1_redirect_boundary_still_enforced_in_discovery():
 seen=[]
 async def h(req): seen.append(str(req.url)); return httpx.Response(302,headers={'Location':'https://outside.test/'})
 p=ScopePolicy([ScopePolicy.parse_rule('app.test')]); d=await DiscoveryService(ControlledTransport(p,transport=httpx.MockTransport(h),rate_per_second=10000)).discover('https://app.test/')
 assert len(seen)==1 and d['redirect_chain'][0].followed is False

def test_phase2_evidence_does_not_persist_state_nonce_or_authorization_url(tmp_path):
 import asyncio
 from tazama_oauth.evidence.store import EvidenceStore
 html='<a href="https://app.test/authorize?response_type=code&state=STATESECRET&nonce=NONCESECRET&code=CODESECRET">login</a>'
 async def h(req): return httpx.Response(200,text=html)
 p=ScopePolicy([ScopePolicy.parse_rule('app.test')]); svc=DiscoveryService(ControlledTransport(p,transport=httpx.MockTransport(h),rate_per_second=10000),EvidenceStore(tmp_path))
 d=asyncio.run(svc.discover('https://app.test/')); raw=''.join(x.read_text() for x in tmp_path.glob('*.json'))
 assert d['evidence_ids'] and 'STATESECRET' not in raw and 'NONCESECRET' not in raw and 'CODESECRET' not in raw
