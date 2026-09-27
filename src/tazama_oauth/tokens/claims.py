from datetime import datetime,timezone
from tazama_oauth.evidence.redaction import fingerprint
def analyze_time(claims,now=None,leeway=0,long_lifetime=86400):
 now=(now or datetime.now(timezone.utc)).timestamp(); out={}
 exp=claims.get('exp'); iat=claims.get('iat'); nbf=claims.get('nbf')
 out['expiration']='EXP_MISSING' if exp is None else ('EXPIRED' if exp+leeway<now else 'NOT_EXPIRED')
 if nbf is not None: out['nbf']='NOT_YET_VALID' if nbf-leeway>now else 'NBF_PRESENT'
 if iat is not None: out['iat']='IAT_IN_FUTURE' if iat-leeway>now else 'IAT_PRESENT'
 if exp is not None and iat is not None:
  out['lifetime_seconds']=exp-iat
  if exp-iat>long_lifetime: out['lifetime']='LONG_LIFETIME'
 else: out['lifetime']='LIFETIME_UNKNOWN'
 return out
def validate_claims(claims,issuer=None,audience=None,nonce=None,client_id=None,now=None,leeway=0):
 t=analyze_time(claims,now,leeway); r={'expiration':'VALID' if t['expiration']=='NOT_EXPIRED' else ('NOT_TESTED' if t['expiration']=='EXP_MISSING' else 'INVALID'),'nbf':'VALID' if t.get('nbf')!='NOT_YET_VALID' else 'INVALID','iat':'VALID' if t.get('iat')!='IAT_IN_FUTURE' else 'INVALID'}
 r['issuer']='NOT_TESTED' if issuer is None else ('VALID' if claims.get('iss')==issuer else 'INVALID')
 aud=claims.get('aud'); audiences=[aud] if isinstance(aud,str) else (aud or [])
 r['audience']='NOT_TESTED' if audience is None else ('VALID' if audience in audiences else 'INVALID')
 if len(audiences)>1 and client_id is not None:r['azp']='VALID' if claims.get('azp')==client_id else 'INVALID'
 else:r['azp']='NOT_TESTED'
 r['nonce']='NOT_TESTED' if nonce is None else ('VALID' if claims.get('nonce')==nonce else 'INVALID')
 return r
def safe_claims(claims):
 out=dict(claims)
 if 'sub' in out: out['sub_fingerprint']=fingerprint(str(out.pop('sub')))
 if 'nonce' in out: out['nonce']='[PRESENT]'
 if 'jti' in out: out['jti_fingerprint']=fingerprint(str(out.pop('jti')))
 return out
