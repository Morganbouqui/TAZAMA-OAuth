from urllib.parse import urlsplit, parse_qs
from tazama_oauth.oauth.models import AuthorizationRequest
KNOWN={'client_id','redirect_uri','response_type','response_mode','scope','state','nonce','code_challenge','code_challenge_method','prompt','audience','resource'}
def parse_authorization_url(url:str)->AuthorizationRequest:
    p=urlsplit(url)
    if p.scheme not in {'http','https'} or not p.netloc: raise ValueError('malformed authorization URL')
    q=parse_qs(p.query,keep_blank_values=True)
    def one(k): return q.get(k,[None])[0]
    def words(k): return [x for v in q.get(k,[]) for x in v.split() if x]
    additional={k:list(v) for k,v in q.items() if k not in KNOWN}
    repeated={k:list(v) for k,v in q.items() if len(v)>1}
    return AuthorizationRequest(url=url,client_id=one('client_id'),redirect_uri=one('redirect_uri'),response_type=words('response_type'),response_mode=one('response_mode'),scopes=words('scope'),state=one('state'),nonce=one('nonce'),code_challenge=one('code_challenge'),code_challenge_method=one('code_challenge_method'),prompt=words('prompt'),audience=q.get('audience',[]),resource=q.get('resource',[]),additional=additional,repeated=repeated)
