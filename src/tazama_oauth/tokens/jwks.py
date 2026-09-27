import base64
from dataclasses import dataclass
@dataclass(slots=True)
class KeySelection:
 key:dict|None; status:str; candidates:int
def parse_jwks(data):
 if not isinstance(data,dict) or not isinstance(data.get('keys'),list): raise ValueError('invalid JWKS')
 return [k for k in data['keys'] if isinstance(k,dict)]
def select_key(keys,*,kid=None,alg=None,kty=None):
 c=[k for k in keys if (kid is None or k.get('kid')==kid) and (alg is None or k.get('alg') in (None,alg)) and (kty is None or k.get('kty')==kty) and k.get('use') in (None,'sig')]
 if not c:return KeySelection(None,'NO_MATCH',0)
 if len(c)>1:return KeySelection(None,'AMBIGUOUS',len(c))
 return KeySelection(c[0],'SELECTED',1)
def b64int(s): return int.from_bytes(base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4)),'big')
