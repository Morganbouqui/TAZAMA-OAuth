from tazama_oauth.oauth.models import FlowObservation,FlowBasis,AuthorizationRequest
from tazama_oauth.oidc.metadata import ProviderMetadata
def observed_flows(req:AuthorizationRequest):
    rt=set(req.response_type); out=[]
    if 'code' in rt:
        name='Authorization Code + PKCE' if req.code_challenge else 'Authorization Code'; out.append(FlowObservation(name,FlowBasis.OBSERVED,[req.url]))
    if 'token' in rt and 'code' not in rt: out.append(FlowObservation('Implicit',FlowBasis.OBSERVED,[req.url]))
    if 'code' in rt and ({'token','id_token'} & rt): out.append(FlowObservation('Hybrid',FlowBasis.OBSERVED,[req.url]))
    if 'id_token' in rt and 'code' not in rt and 'token' not in rt: out.append(FlowObservation('OIDC Implicit',FlowBasis.OBSERVED,[req.url]))
    return out
def supported_flows(meta:ProviderMetadata):
    out=[]; rts=meta.capabilities.get('response_types_supported',[]) or []; grants=meta.capabilities.get('grant_types_supported',[]) or []
    if any(set(str(x).split())=={'code'} for x in rts): out.append(FlowObservation('Authorization Code',FlowBasis.SUPPORTED,['metadata']))
    if any('token' in str(x).split() and 'code' not in str(x).split() for x in rts): out.append(FlowObservation('Implicit',FlowBasis.SUPPORTED,['metadata']))
    if any('code' in str(x).split() and ({'token','id_token'}&set(str(x).split())) for x in rts): out.append(FlowObservation('Hybrid',FlowBasis.SUPPORTED,['metadata']))
    if 'client_credentials' in grants: out.append(FlowObservation('Client Credentials',FlowBasis.SUPPORTED,['metadata']))
    if 'urn:ietf:params:oauth:grant-type:device_code' in grants: out.append(FlowObservation('Device Authorization',FlowBasis.SUPPORTED,['metadata']))
    return out
