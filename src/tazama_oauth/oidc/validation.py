from dataclasses import dataclass,asdict
from tazama_oauth.tokens.parser import decode
from tazama_oauth.tokens.claims import validate_claims
from tazama_oauth.tokens.verify import verify_jwks,verify_hmac
@dataclass(slots=True)
class IDTokenValidation:
 signature:str; issuer:str; audience:str; azp:str; expiration:str; iat:str; nbf:str; nonce:str; overall:str; expectation_sources:dict
 def as_dict(self):return asdict(self)
def validate_id_token(token,*,keys=None,hmac_secret=None,issuer=None,audience=None,nonce=None,client_id=None,leeway=0,sources=None):
 d=decode(token)
 if hmac_secret is not None:v=verify_hmac(token,hmac_secret)
 elif keys is not None:v=verify_jwks(token,keys)
 else:v=None
 c=validate_claims(d.claims,issuer,audience,nonce,client_id,leeway=leeway)
 sig=v.signature if v else 'NOT_TESTED'
 tested=[sig,c['issuer'],c['audience'],c['expiration'],c['azp'],c['nonce']]
 overall='CLAIMS_VALIDATED' if sig=='VERIFIED' and all(x in {'VALID','NOT_TESTED'} for x in tested[1:]) else 'CLAIMS_PARTIALLY_VALIDATED'
 return IDTokenValidation(sig,c['issuer'],c['audience'],c['azp'],c['expiration'],c['iat'],c['nbf'],c['nonce'],overall,sources or {})
