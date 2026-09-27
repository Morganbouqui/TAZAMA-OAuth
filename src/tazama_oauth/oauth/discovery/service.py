import json,re
from html.parser import HTMLParser
from urllib.parse import urljoin
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.oauth.parser import parse_authorization_url
from tazama_oauth.oauth.models import EndpointObservation
from tazama_oauth.oidc.metadata import parse_provider_metadata,classify_metadata_endpoints
from tazama_oauth.evidence.models import EvidenceRecord
URL_RE=re.compile(r'https?://[^\s"\'<>]+')
OAUTH_TERMS=('oauth','oidc','authorize','authorization','openid','login','sso','.well-known')
class _HTMLRefs(HTMLParser):
    def __init__(self): super().__init__(); self.refs=[]
    def handle_starttag(self,tag,attrs):
        d=dict(attrs)
        for k in ('href','src','action'):
            if d.get(k): self.refs.append(d[k])
class DiscoveryService:
    def __init__(self,transport:ControlledTransport,evidence_store=None): self.transport=transport; self.evidence_store=evidence_store
    def _evidence(self,target,module,result):
        rec=EvidenceRecord(target,module,{'url':target,'headers':{},'body':None},{'status':result.status,'headers':result.headers,'body':None,'content_type':result.headers.get('content-type','')},result.redirect_chain)
        if self.evidence_store: self.evidence_store.save(rec)
        return rec.evidence_id
    async def discover(self,target:str):
        result=await self.transport.request('GET',target); evidence_id=self._evidence(target,'oauth.discovery',result)
        refs=[]; parser=_HTMLRefs(); parser.feed(result.body); refs += [urljoin(target,x) for x in parser.refs]; refs += URL_RE.findall(result.body); refs=list(dict.fromkeys(refs)); auth=[]; endpoints=[]
        for u in refs:
            low=u.lower()
            if any(t in low for t in OAUTH_TERMS):
                typ='authorization' if ('authorize' in low or 'authorization' in low) else 'reference'
                endpoints.append(EndpointObservation(typ,u,'html','IN_SCOPE' if self.transport.scope.allows_url(u) else 'OUT_OF_SCOPE','html',evidence_ids=[evidence_id]))
                if 'client_id=' in u or 'response_type=' in u:
                    try:
                        r=parse_authorization_url(u); r.evidence_ids.append(evidence_id); auth.append(r)
                    except ValueError: pass
        return {'target':target,'http_status':result.status,'oauth_detected':bool(endpoints or auth),'authorization_requests':auth,'endpoints':endpoints,'redirect_chain':result.redirect_chain,'evidence_ids':[evidence_id]}
    async def oidc_discover(self,target:str):
        metadata_url=urljoin(target.rstrip('/')+'/', '.well-known/openid-configuration'); result=await self.transport.request('GET',metadata_url); evidence_id=self._evidence(metadata_url,'oidc.discovery',result)
        try: data=json.loads(result.body)
        except json.JSONDecodeError: data={}
        meta=parse_provider_metadata(data); endpoints=classify_metadata_endpoints(meta,self.transport.scope)
        for e in endpoints: e.evidence_ids.append(evidence_id)
        return meta,endpoints,result
