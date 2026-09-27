import pytest,httpx
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.tokens.service import JWKSService
@pytest.mark.asyncio
async def test_out_of_scope_jwks_zero_requests():
 calls=[]
 async def h(req):calls.append(str(req.url));return httpx.Response(200,json={'keys':[]})
 s=JWKSService(ControlledTransport(ScopePolicy([ScopePolicy.parse_rule('app.test')]),transport=httpx.MockTransport(h)))
 r=await s.fetch('https://identity.external.test/keys');assert r['scope_status']=='OUT_OF_SCOPE' and r['request_status']=='NOT_REQUESTED' and calls==[]
@pytest.mark.asyncio
async def test_in_scope_jwks():
 calls=[]
 async def h(req):calls.append(str(req.url));return httpx.Response(200,json={'keys':[{'kty':'RSA','kid':'x'}]})
 s=JWKSService(ControlledTransport(ScopePolicy([ScopePolicy.parse_rule('keys.test')]),transport=httpx.MockTransport(h)))
 r=await s.fetch('https://keys.test/jwks');assert r['request_status']=='REQUESTED' and len(r['keys'])==1 and len(calls)==1
