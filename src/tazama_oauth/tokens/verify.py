import base64,hashlib,hmac
from tazama_oauth.tokens.parser import decode
from tazama_oauth.tokens.models import VerificationResult
from tazama_oauth.tokens.jwks import select_key,b64int
def _b64(s): return base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
def verify_hmac(token,secret:bytes):
 d=decode(token); alg=d.header.get('alg'); hashes={'HS256':hashlib.sha256,'HS384':hashlib.sha384,'HS512':hashlib.sha512}
 if alg not in hashes:return VerificationResult(alg,'explicit HMAC secret',d.header.get('kid'),None,'ALGORITHM_KEY_INCOMPATIBLE')
 p=token.split('.'); expected=hmac.new(secret,(p[0]+'.'+p[1]).encode(),hashes[alg]).digest(); ok=hmac.compare_digest(expected,_b64(p[2]))
 return VerificationResult(alg,'explicit HMAC secret',d.header.get('kid'),'shared-secret','VERIFIED' if ok else 'INVALID')
def verify_jwks(token,keys):
 d=decode(token); alg=d.header.get('alg'); kty='RSA' if alg in {'RS256','RS384','RS512'} else 'EC' if alg in {'ES256','ES384'} else None
 if not kty:return VerificationResult(alg,'JWKS',d.header.get('kid'),None,'UNSUPPORTED_ALGORITHM')
 s=select_key(keys,kid=d.header.get('kid'),alg=alg,kty=kty)
 if s.status!='SELECTED':return VerificationResult(alg,'JWKS',d.header.get('kid'),None,s.status)
 try:
  from cryptography.hazmat.primitives.asymmetric import rsa,ec
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
  p=token.split('.'); sig=_b64(p[2]); data=(p[0]+'.'+p[1]).encode(); k=s.key
  if kty=='RSA':
   pub=rsa.RSAPublicNumbers(b64int(k['e']),b64int(k['n'])).public_key(); hm={'RS256':hashes.SHA256(),'RS384':hashes.SHA384(),'RS512':hashes.SHA512()}[alg]; pub.verify(sig,data,PKCS1v15(),hm)
  else:return VerificationResult(alg,'JWKS',d.header.get('kid'),k.get('kid'),'UNSUPPORTED_ALGORITHM')
  return VerificationResult(alg,'JWKS',d.header.get('kid'),k.get('kid'),'VERIFIED')
 except Exception:return VerificationResult(alg,'JWKS',d.header.get('kid'),s.key.get('kid'),'INVALID')
