import pytest,httpx
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.scope.models import CallbackRule
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.core.errors import ScopeDenied
@pytest.mark.asyncio
async def test_target_argument_does_not_authorize_target():
 calls=0
 async def h(req):
  nonlocal calls; calls+=1; return httpx.Response(200)
 t=ControlledTransport(ScopePolicy([]),transport=httpx.MockTransport(h))
 with pytest.raises(ScopeDenied): await t.request('GET','https://outside.test/')
 assert calls==0
@pytest.mark.asyncio
async def test_active_does_not_expand_scope():
 calls=0
 async def h(req):
  nonlocal calls; calls+=1; return httpx.Response(200)
 t=ControlledTransport(ScopePolicy([ScopePolicy.parse_rule('app.test')]),transport=httpx.MockTransport(h))
 with pytest.raises(ScopeDenied): await t.request('GET','https://outside.test/')
 assert calls==0
def test_callback_still_not_assessment_scope():
 p=ScopePolicy([], [CallbackRule('https://callback.test/cb')]); assert p.allows_callback('https://callback.test/cb'); assert not p.allows_url('https://callback.test/cb')
def test_existing_wildcard_cidr_semantics():
 p=ScopePolicy([ScopePolicy.parse_rule('*.example.test'),ScopePolicy.parse_rule('10.0.0.0/8')]); assert p.allows_url('https://a.example.test/'); assert not p.allows_url('https://example.test/'); assert p.allows_url('http://10.2.3.4/')
