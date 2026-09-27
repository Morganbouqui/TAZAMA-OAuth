import json,pytest,httpx
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.core.errors import ScopeDenied
from tazama_oauth.evidence.models import EvidenceRecord
from tazama_oauth.evidence.store import EvidenceStore
@pytest.mark.asyncio
async def test_no_network_without_scope():
 calls=0
 async def handler(req):
  nonlocal calls; calls+=1; return httpx.Response(200,text="bad")
 t=ControlledTransport(ScopePolicy([]),transport=httpx.MockTransport(handler))
 with pytest.raises(ScopeDenied): await t.request("GET","https://outside.test/")
 assert calls==0
@pytest.mark.asyncio
async def test_in_scope_redirect_followed():
 seen=[]
 async def handler(req):
  seen.append(str(req.url));
  if req.url.path=="/start": return httpx.Response(302,headers={"Location":"/end"})
  return httpx.Response(200,text="done")
 p=ScopePolicy([ScopePolicy.parse_rule("inside.test")]); t=ControlledTransport(p,transport=httpx.MockTransport(handler),rate_per_second=10000)
 r=await t.request("GET","https://inside.test/start"); assert r.status==200 and len(seen)==2 and r.redirect_chain[0].followed
@pytest.mark.asyncio
async def test_out_of_scope_redirect_recorded_not_followed():
 seen=[]
 async def handler(req): seen.append(str(req.url)); return httpx.Response(302,headers={"Location":"https://outside.test/secret"})
 p=ScopePolicy([ScopePolicy.parse_rule("inside.test")]); t=ControlledTransport(p,transport=httpx.MockTransport(handler),rate_per_second=10000)
 r=await t.request("GET","https://inside.test/start"); assert len(seen)==1; assert r.status==302; assert r.redirect_chain[0].scope_allowed is False; assert r.redirect_chain[0].followed is False; assert "outside.test" in r.redirect_chain[0].location
@pytest.mark.asyncio
async def test_redirect_loop_is_bounded_and_structured():
 seen=[]
 async def handler(req):
  seen.append(str(req.url)); return httpx.Response(302,headers={"Location":"/loop"})
 p=ScopePolicy([ScopePolicy.parse_rule("inside.test")]); t=ControlledTransport(p,transport=httpx.MockTransport(handler),rate_per_second=10000,max_redirects=2)
 with pytest.raises(httpx.TooManyRedirects,match="redirect limit exceeded"): await t.request("GET","https://inside.test/loop")
 assert len(seen)==3

def test_persisted_evidence_has_no_raw_secrets(tmp_path):
 rec=EvidenceRecord("inside.test","test",{"url":"https://inside.test/?access_token=URLSECRET","headers":{"Authorization":"Bearer HEADERSECRET","Cookie":"sid=COOKIESECRET"},"body":"client_secret=FORMSECRET&x=ok","content_type":"application/x-www-form-urlencoded"},{"headers":{"Set-Cookie":"sid=RESPONSESECRET"},"body":{"access_token":"JSONSECRET"},"content_type":"application/json"})
 path=EvidenceStore(tmp_path).save(rec); raw=path.read_text()
 for s in ["URLSECRET","HEADERSECRET","COOKIESECRET","FORMSECRET","RESPONSESECRET","JSONSECRET"]: assert s not in raw
 assert "[REDACTED]" in raw and "SHA256:" in raw

@pytest.mark.asyncio
async def test_dry_run_makes_no_network_request():
 calls=0
 async def handler(req):
  nonlocal calls; calls+=1; return httpx.Response(200)
 p=ScopePolicy([ScopePolicy.parse_rule("inside.test")]); t=ControlledTransport(p,transport=httpx.MockTransport(handler))
 r=await t.request("GET","https://inside.test/",dry_run=True); assert r.status==0 and calls==0

def test_redirect_chain_persists_as_evidence(tmp_path):
 from tazama_oauth.evidence.models import RedirectHop
 rec=EvidenceRecord("inside.test","redirect",{"url":"https://inside.test/start","headers":{},"body":None},{"headers":{},"body":"","content_type":"text/plain"},[RedirectHop("https://inside.test/start",302,"https://outside.test/",False,False)])
 raw=EvidenceStore(tmp_path).save(rec).read_text(); data=json.loads(raw); assert data["redirect_chain"][0]["scope_allowed"] is False and data["redirect_chain"][0]["followed"] is False
