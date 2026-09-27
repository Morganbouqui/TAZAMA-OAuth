import base64,json,hmac,hashlib,pytest
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from tazama_oauth.tokens.verify import verify_jwks,verify_hmac
from tazama_oauth.tokens.jwks import select_key,parse_jwks
def enc(x):return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def js(x):return enc(json.dumps(x,separators=(',',':')).encode())
def rsa_fixture(kid='k1'):
 priv=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=priv.public_key().public_numbers()
 jwk={'kty':'RSA','kid':kid,'use':'sig','alg':'RS256','n':enc(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':enc(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}
 return priv,jwk
def test_rs256_valid_invalid_wrong_unknown_ambiguous():
 priv,jwk=rsa_fixture();h=js({'alg':'RS256','kid':'k1','typ':'JWT'});p=js({'iss':'i'});data=f'{h}.{p}'.encode();sig=enc(priv.sign(data,padding.PKCS1v15(),hashes.SHA256()));t=f'{h}.{p}.{sig}'
 assert verify_jwks(t,[jwk]).signature=='VERIFIED'
 assert verify_jwks(t[:-2]+'aa',[jwk]).signature=='INVALID'
 _,wrong=rsa_fixture('k1');assert verify_jwks(t,[wrong]).signature=='INVALID'
 assert verify_jwks(t,[dict(jwk,kid='other')]).signature=='NO_MATCH'
 assert verify_jwks(t,[jwk,dict(jwk)]).signature=='AMBIGUOUS'
def test_hs256_valid_invalid_and_incompatible():
 secret=b'fixture-secret';h=js({'alg':'HS256','typ':'JWT'});p=js({'sub':'x'});data=f'{h}.{p}'.encode();t=f'{h}.{p}.{enc(hmac.new(secret,data,hashlib.sha256).digest())}'
 assert verify_hmac(t,secret).signature=='VERIFIED';assert verify_hmac(t,b'wrong').signature=='INVALID'
 rh=js({'alg':'RS256','typ':'JWT'});rt=f'{rh}.{p}.abc';assert verify_hmac(rt,secret).signature=='ALGORITHM_KEY_INCOMPATIBLE'
def test_key_selection_constraints():
 _,a=rsa_fixture('a');_,b=rsa_fixture('b');keys=parse_jwks({'keys':[a,b]})
 assert select_key(keys,kid='b',alg='RS256',kty='RSA').key['kid']=='b'
 assert select_key(keys,kid='missing').status=='NO_MATCH'
 assert select_key(keys,alg='RS256',kty='RSA').status=='AMBIGUOUS'
 assert select_key(keys,kid='a',alg='ES256').status=='NO_MATCH'
