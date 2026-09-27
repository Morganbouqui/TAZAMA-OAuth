import hashlib
from urllib.parse import urlsplit,parse_qs
from tazama_oauth.testing.models import DifferentialObservation
from tazama_oauth.testing.baseline import Baseline
from tazama_oauth.http.models import HTTPResult
def _h(s): return 'SHA256:'+hashlib.sha256(s.encode()).hexdigest()
def _params(result):
    vals={}
    for candidate in [result.headers.get('location','')]:
        if candidate: vals.update({k:v[0] for k,v in parse_qs(urlsplit(candidate).query).items() if v})
    return vals
def compare(b:Baseline,r:HTTPResult)->DifferentialObservation:
    p=_params(r)
    return DifferentialObservation(b.response_status!=r.status,b.location!=r.headers.get('location'),b.redirect_chain!=[vars(x) if hasattr(x,'__dict__') else {'url':x.url,'status':x.status,'location':x.location,'followed':x.followed,'scope_allowed':x.scope_allowed} for x in r.redirect_chain],b.response_body_fingerprint!=_h(r.body),len(r.body)-b.response_length,p.get('error'),p.get('error_description'),'code' in p,any(k in p for k in {'access_token','id_token'}))
