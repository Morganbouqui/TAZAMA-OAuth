import base64,json,hmac,hashlib
from tazama_oauth.oidc.validation import validate_id_token
def e(x):return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def token(secret=b's'):
 h=e(json.dumps({'alg':'HS256','typ':'JWT'}).encode());p=e(json.dumps({'iss':'issuer','aud':['a','b'],'azp':'client','nonce':'n','exp':4102444800,'iat':1000}).encode());d=f'{h}.{p}'.encode();return f'{h}.{p}.{e(hmac.new(secret,d,hashlib.sha256).digest())}'
def test_id_token_validation_components():
 r=validate_id_token(token(),hmac_secret=b's',issuer='issuer',audience='a',nonce='n',client_id='client',sources={'issuer':'explicit CLI'})
 assert r.signature=='VERIFIED' and r.issuer=='VALID' and r.audience=='VALID' and r.azp=='VALID' and r.nonce=='VALID' and r.overall=='CLAIMS_VALIDATED'
def test_id_token_mismatches_visible():
 r=validate_id_token(token(),hmac_secret=b'bad',issuer='wrong',audience='z',nonce='bad',client_id='wrong')
 assert r.signature=='INVALID' and r.issuer=='INVALID' and r.audience=='INVALID' and r.nonce=='INVALID'
