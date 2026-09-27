import base64,json
from datetime import datetime,timezone
import pytest
from tazama_oauth.tokens.parser import classify,decode
from tazama_oauth.tokens.models import TokenType
from tazama_oauth.tokens.claims import analyze_time,validate_claims,safe_claims
from tazama_oauth.tokens.observations import jose_observations
def b(o):return base64.urlsafe_b64encode(json.dumps(o,ensure_ascii=False).encode()).rstrip(b'=').decode()
def tok(h,p,s='sig'):return f'{b(h)}.{b(p)}.{s}'
def test_classifier_and_parser():
 assert classify('opaque-token')==TokenType.OPAQUE
 t=tok({'alg':'RS256','typ':'JWT','x-extra':1},{'sub':'秘密','custom':{'x':1},'aud':['a','b']})
 d=decode(t);assert d.token_type==TokenType.JWT and d.claims['sub']=='秘密' and d.header['x-extra']==1 and d.claims['custom']=={'x':1}
 assert classify('@@@.e30.sig')==TokenType.UNKNOWN
 assert classify('e30.bm90anNvbg.sig')==TokenType.UNKNOWN
 assert classify('a.b.c.d')==TokenType.UNKNOWN
 assert classify('a.b.c.d.e')==TokenType.JWE_LIKE
def test_missing_signature_structurally_decodes():
 d=decode(tok({'alg':'none','typ':'JWT'},{'iss':'x'},''));assert not d.signature_present and 'ALG_NONE' in jose_observations(d)
def test_time_claims_and_leeway():
 now=1000
 assert analyze_time({'exp':1100,'iat':900,'nbf':900},now)['expiration']=='NOT_EXPIRED'
 assert analyze_time({'exp':900},now)['expiration']=='EXPIRED'
 assert analyze_time({},now)['expiration']=='EXP_MISSING'
 assert analyze_time({'nbf':1100},now)['nbf']=='NOT_YET_VALID'
 assert analyze_time({'iat':1100},now)['iat']=='IAT_IN_FUTURE'
 assert analyze_time({'exp':995},now,leeway=10)['expiration']=='NOT_EXPIRED'
def test_datetime_and_float_now_inputs():
 dt=datetime.fromtimestamp(1000,tz=timezone.utc)
 assert analyze_time({'exp':1001},dt)['expiration']=='NOT_EXPIRED'
 assert analyze_time({'exp':1001},1000.5)['expiration']=='NOT_EXPIRED'
def test_invalid_time_inputs_fail_safely():
 with pytest.raises(ValueError,match='now must'): analyze_time({'exp':1100},'1000')
 with pytest.raises(ValueError,match='timezone-aware'): analyze_time({'exp':1100},datetime(1970,1,1))
 for claim in ('exp','iat','nbf'):
  with pytest.raises(ValueError,match='NumericDate'): analyze_time({claim:'bad'},1000)
 r=validate_claims({'exp':'bad'},audience='a',now=1000);assert r['expiration']=='INVALID' and 'time_error' in r
 assert validate_claims({'aud':{'unexpected':'type'}},audience='a',now=1000)['audience']=='INVALID'
def test_expected_claims():
 c={'iss':'i','aud':['a','b'],'azp':'client','nonce':'n','exp':2000,'iat':900,'nbf':800}
 r=validate_claims(c,'i','a','n','client',now=1000);assert all(r[x]=='VALID' for x in ['issuer','audience','azp','nonce','expiration','iat','nbf'])
 assert validate_claims(c,'wrong','z','bad','wrong',now=1000)['issuer']=='INVALID'
def test_safe_subject_fingerprint():
 s=safe_claims({'sub':'secret-sub','jti':'id','nonce':'n'});assert 'secret-sub' not in str(s) and s['sub_fingerprint'].startswith('SHA256:')
