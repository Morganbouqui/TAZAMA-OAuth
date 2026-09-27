from tazama_oauth.oauth.parser import parse_authorization_url
from tazama_oauth.oauth.flow.mapper import observed_flows,supported_flows
from tazama_oauth.oidc.metadata import parse_provider_metadata

def flow(url): return [x.flow for x in observed_flows(parse_authorization_url(url))]
def test_code(): assert 'Authorization Code' in flow('https://id/a?response_type=code')
def test_code_pkce(): assert 'Authorization Code + PKCE' in flow('https://id/a?response_type=code&code_challenge=x&code_challenge_method=S256')
def test_implicit(): assert 'Implicit' in flow('https://id/a?response_type=token')
def test_hybrid(): assert 'Hybrid' in flow('https://id/a?response_type=code%20id_token')
def test_supported_not_observed():
 f=supported_flows(parse_provider_metadata({'response_types_supported':['code']})); assert f[0].basis.value=='SUPPORTED'
