import base64,json,re
from tazama_oauth.evidence.redaction import fingerprint
from tazama_oauth.tokens.models import TokenType,DecodedToken,VerificationState
B64=re.compile(r'^[A-Za-z0-9_-]*$')
def _decode(s):
 if not B64.fullmatch(s): raise ValueError('malformed base64url')
 return base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
def classify(token:str)->TokenType:
 parts=token.strip().split('.')
 if len(parts)==5 and all(B64.fullmatch(x or '') for x in parts): return TokenType.JWE_LIKE
 if len(parts)!=3: return TokenType.OPAQUE if '.' not in token else TokenType.UNKNOWN
 try:
  h=json.loads(_decode(parts[0])); p=json.loads(_decode(parts[1]))
  if not isinstance(h,dict) or not isinstance(p,dict): return TokenType.UNKNOWN
  return TokenType.JWT if h.get('typ','').upper()=='JWT' or isinstance(p,dict) else TokenType.JWS
 except Exception:return TokenType.UNKNOWN
def decode(token:str)->DecodedToken:
 raw=token.strip(); typ=classify(raw); parts=raw.split('.')
 if typ not in {TokenType.JWT,TokenType.JWS}: return DecodedToken(typ,len(parts),fingerprint=fingerprint(raw))
 try:
  header=json.loads(_decode(parts[0])); claims=json.loads(_decode(parts[1]))
 except Exception:return DecodedToken(TokenType.UNKNOWN,len(parts),fingerprint=fingerprint(raw))
 return DecodedToken(typ,3,header,claims,bool(parts[2]),VerificationState.STRUCTURALLY_VALID,fingerprint(raw))
