from datetime import datetime,timezone
from numbers import Real
from tazama_oauth.evidence.redaction import fingerprint
def _numeric_date(value,name):
 if isinstance(value,bool) or not isinstance(value,Real): raise ValueError(f'{name} must be a NumericDate')
 return float(value)
def _now_timestamp(now):
 if now is None:return datetime.now(timezone.utc).timestamp()
 if isinstance(now,datetime):
  if now.tzinfo is None: raise ValueError('now datetime must be timezone-aware')
  return now.timestamp()
 if isinstance(now,bool) or not isinstance(now,Real): raise ValueError('now must be None, datetime, or Unix timestamp')
 return float(now)
def analyze_time(claims,now=None,leeway=0,long_lifetime=86400):
 now_ts=_now_timestamp(now); out={}
 exp=claims.get('exp'); iat=claims.get('iat'); nbf=claims.get('nbf')
 expv=None if exp is None else _numeric_date(exp,'exp'); iatv=None if iat is None else _numeric_date(iat,'iat'); nbfv=None if nbf is None else _numeric_date(nbf,'nbf')
 out['expiration']='EXP_MISSING' if expv is None else ('EXPIRED' if expv+leeway<now_ts else 'NOT_EXPIRED')
 if nbfv is not None: out['nbf']='NOT_YET_VALID' if nbfv-leeway>now_ts else 'NBF_PRESENT'
 if iatv is not None: out['iat']='IAT_IN_FUTURE' if iatv-leeway>now_ts else 'IAT_PRESENT'
 if expv is not None and iatv is not None:
  out['lifetime_seconds']=expv-iatv
  if expv-iatv>long_lifetime: out['lifetime']='LONG_LIFETIME'
 else: out['lifetime']='LIFETIME_UNKNOWN'
 return out
def validate_claims(claims,issuer=None,audience=None,nonce=None,client_id=None,now=None,leeway=0):
 try:t=analyze_time(claims,now,leeway)
 except (TypeError,ValueError) as exc:return {'expiration':'INVALID','nbf':'INVALID','iat':'INVALID','issuer':'NOT_TESTED' if issuer is None else ('VALID' if claims.get('iss')==issuer else 'INVALID'),'audience':'INVALID' if audience is not None else 'NOT_TESTED','azp':'NOT_TESTED','nonce':'NOT_TESTED' if nonce is None else ('VALID' if claims.get('nonce')==nonce else 'INVALID'),'time_error':str(exc)}
 r={'expiration':'VALID' if t['expiration']=='NOT_EXPIRED' else ('NOT_TESTED' if t['expiration']=='EXP_MISSING' else 'INVALID'),'nbf':'VALID' if t.get('nbf')!='NOT_YET_VALID' else 'INVALID','iat':'VALID' if t.get('iat')!='IAT_IN_FUTURE' else 'INVALID'}
 r['issuer']='NOT_TESTED' if issuer is None else ('VALID' if claims.get('iss')==issuer else 'INVALID')
 aud=claims.get('aud')
 if aud is None:audiences=[]
 elif isinstance(aud,str):audiences=[aud]
 elif isinstance(aud,list) and all(isinstance(x,str) for x in aud):audiences=aud
 else:
  r['audience']='INVALID' if audience is not None else 'NOT_TESTED'; audiences=[]
 if 'audience' not in r:r['audience']='NOT_TESTED' if audience is None else ('VALID' if audience in audiences else 'INVALID')
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
