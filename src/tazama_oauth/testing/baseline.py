import hashlib
from dataclasses import dataclass,asdict,field
from urllib.parse import urlsplit,parse_qsl
from uuid import uuid4
from tazama_oauth.http.models import HTTPResult
from tazama_oauth.evidence.redaction import redact_url,redact_headers
@dataclass(slots=True)
class Baseline:
    method:str; url:str; query:list[tuple[str,str]]; headers:dict; body_fingerprint:str|None; response_status:int; location:str|None
    redirect_chain:list[dict]; content_type:str; response_body_fingerprint:str; response_length:int; oauth_parameters:dict
    evidence_id:str|None=None; baseline_id:str=field(default_factory=lambda:str(uuid4()))
    def as_dict(self): return asdict(self)
def _hash(v:str|bytes|None):
    if v is None:return None
    b=v if isinstance(v,bytes) else v.encode(); return 'SHA256:'+hashlib.sha256(b).hexdigest()
def create_baseline(method:str,url:str,headers:dict,body:str|bytes|None,result:HTTPResult,evidence_id=None):
    q=parse_qsl(urlsplit(url).query,keep_blank_values=True); oq={k:v for k,v in q if k in {'client_id','redirect_uri','response_type','response_mode','scope','state','nonce','code_challenge','code_challenge_method'}}
    safe_q=[(k,'[REDACTED]' if k in {'code','access_token','refresh_token','id_token','client_secret','state','nonce'} else v) for k,v in q]
    return Baseline(method,redact_url(url),safe_q,redact_headers(headers),_hash(body),result.status,result.headers.get('location'),[asdict(x) for x in result.redirect_chain],result.headers.get('content-type',''),_hash(result.body) or '',len(result.body),{k:('[REDACTED]' if k in {'state','nonce'} else v) for k,v in oq.items()},evidence_id)
