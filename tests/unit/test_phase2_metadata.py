from tazama_oauth.oidc.metadata import parse_provider_metadata,classify_metadata_endpoints
from tazama_oauth.scope.policy import ScopePolicy

def fixture(): return {'issuer':'https://id.test','authorization_endpoint':'https://id.test/authorize','token_endpoint':'https://third.test/token','userinfo_endpoint':'https://id.test/userinfo','jwks_uri':'https://id.test/jwks','revocation_endpoint':'https://id.test/revoke','introspection_endpoint':'https://id.test/introspect','response_types_supported':['code','code id_token'],'code_challenge_methods_supported':['S256'],'custom_metadata':'keep'}
def test_metadata_and_unknown_preserved():
 m=parse_provider_metadata(fixture()); assert m.issuer=='https://id.test'; assert m.endpoints['jwks_uri'].endswith('/jwks'); assert m.endpoints['userinfo_endpoint'].endswith('/userinfo'); assert m.endpoints['revocation_endpoint'].endswith('/revoke'); assert m.endpoints['introspection_endpoint'].endswith('/introspect'); assert m.additional['custom_metadata']=='keep'
def test_endpoint_classification():
 m=parse_provider_metadata(fixture()); p=ScopePolicy([ScopePolicy.parse_rule('id.test')]); e={x.type:x for x in classify_metadata_endpoints(m,p)}; assert e['authorization'].scope_status=='IN_SCOPE'; assert e['token'].scope_status=='OUT_OF_SCOPE'; assert e['token'].request_status=='NOT_REQUESTED'
