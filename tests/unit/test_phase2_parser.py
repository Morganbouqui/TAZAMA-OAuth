import pytest
from tazama_oauth.oauth.parser import parse_authorization_url

def test_authorization_url_full_and_percent_encoding():
 r=parse_authorization_url('https://id.test/authorize?client_id=c&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&response_type=code&response_mode=query&scope=openid%20profile&state=s&nonce=n&code_challenge=abc&code_challenge_method=S256&prompt=login&audience=a&resource=r&custom=x')
 assert r.client_id=='c' and r.redirect_uri=='https://app.test/cb' and r.response_type==['code'] and r.response_mode=='query'
 assert r.scopes==['openid','profile'] and r.state=='s' and r.nonce=='n' and r.code_challenge_method=='S256' and r.additional['custom']==['x']
def test_repeated_parameters_preserved():
 r=parse_authorization_url('https://id.test/a?resource=one&resource=two&custom=a&custom=b'); assert r.resource==['one','two']; assert r.repeated['custom']==['a','b']
def test_malformed_url():
 with pytest.raises(ValueError): parse_authorization_url('/authorize?client_id=x')
