import pytest,httpx
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.scope.models import CallbackRule
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.testing.baseline import create_baseline
from tazama_oauth.testing.engine import DifferentialTestEngine
from tazama_oauth.testing.plans import state_plan,redirect_plan,pkce_plan
from tazama_oauth.core.safety import SafetyPolicy
from tazama_oauth.core.errors import RiskDenied

async def setup_engine(active=False,callbacks=()):
 calls=[]
 async def h(req): calls.append(str(req.url)); return httpx.Response(302,headers={'Location':'https://app.test/cb?error=access_denied'},text='x')
 p=ScopePolicy([ScopePolicy.parse_rule('app.test')],[CallbackRule(x) for x in callbacks]); t=ControlledTransport(p,transport=httpx.MockTransport(h),rate_per_second=10000)
 base_result=httpx.Response
 from tazama_oauth.http.models import HTTPResult
 b=create_baseline('GET','https://app.test/authorize?state=s&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&code_challenge=x&code_challenge_method=S256',{},None,HTTPResult('x',302,{'location':'https://app.test/cb'},'x',[]))
 return DifferentialTestEngine(t,SafetyPolicy(active=active)),b,calls

@pytest.mark.asyncio
@pytest.mark.parametrize('kind',[state_plan,pkce_plan])
async def test_mutations_without_active_send_zero(kind):
 e,b,calls=await setup_engine(False); m=kind(b.url,b.baseline_id).mutations[0]
 with pytest.raises(RiskDenied): await e.execute(b,m)
 assert calls==[]

@pytest.mark.asyncio
async def test_dry_run_sends_zero():
 e,b,calls=await setup_engine(True); m=state_plan(b.url,b.baseline_id).mutations[0]; o=await e.execute(b,m,dry_run=True); assert not o.transmitted and calls==[]

@pytest.mark.asyncio
async def test_active_valid_scope_permits_controlled_mutation():
 e,b,calls=await setup_engine(True); m=state_plan(b.url,b.baseline_id).mutations[0]; o=await e.execute(b,m); assert o.transmitted and len(calls)==1

@pytest.mark.asyncio
async def test_redirect_unauthorized_callback_blocked_zero_requests():
 e,b,calls=await setup_engine(True); m=redirect_plan(b.url,b.baseline_id).mutations[0]; o=await e.execute(b,m,callback_required=True); assert o.blocked_reason=='BLOCKED_BY_SCOPE' and calls==[]

@pytest.mark.asyncio
async def test_redirect_authorized_alternate_can_be_sent():
 e,b,calls=await setup_engine(True,['https://alt.test/cb']); m=redirect_plan(b.url,b.baseline_id,'https://alt.test/cb').mutations[1]; o=await e.execute(b,m,callback_required=True); assert o.transmitted and len(calls)==1
