from dataclasses import dataclass,field,asdict
from tazama_oauth.scope.policy import ScopePolicy
ENDPOINT_FIELDS={'authorization_endpoint':'authorization','token_endpoint':'token','userinfo_endpoint':'userinfo','jwks_uri':'jwks','registration_endpoint':'registration','revocation_endpoint':'revocation','introspection_endpoint':'introspection','end_session_endpoint':'end_session','device_authorization_endpoint':'device_authorization'}
CAPABILITY_FIELDS={'scopes_supported','response_types_supported','response_modes_supported','grant_types_supported','subject_types_supported','id_token_signing_alg_values_supported','code_challenge_methods_supported'}
@dataclass(slots=True)
class ProviderMetadata:
    issuer:str|None; endpoints:dict[str,str]=field(default_factory=dict); capabilities:dict[str,object]=field(default_factory=dict); additional:dict[str,object]=field(default_factory=dict)
    def as_dict(self): return asdict(self)
def parse_provider_metadata(data:dict)->ProviderMetadata:
    known={'issuer',*ENDPOINT_FIELDS,*CAPABILITY_FIELDS}
    return ProviderMetadata(data.get('issuer'),{k:data[k] for k in ENDPOINT_FIELDS if isinstance(data.get(k),str)},{k:data[k] for k in CAPABILITY_FIELDS if k in data},{k:v for k,v in data.items() if k not in known})
def classify_metadata_endpoints(meta:ProviderMetadata,scope:ScopePolicy):
    from tazama_oauth.oauth.models import EndpointObservation
    return [EndpointObservation(ENDPOINT_FIELDS[k],u,'provider_metadata','IN_SCOPE' if scope.allows_url(u) else 'OUT_OF_SCOPE','metadata',meta.issuer) for k,u in meta.endpoints.items()]
