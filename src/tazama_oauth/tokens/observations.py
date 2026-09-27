def jose_observations(decoded,expected_alg=None):
 h=decoded.header; out=[]
 alg=h.get('alg')
 if alg is None:out.append('MISSING_ALG')
 if alg=='none':out.append('ALG_NONE')
 if expected_alg and alg!=expected_alg:out.append('UNEXPECTED_ALGORITHM')
 if isinstance(alg,str) and alg.startswith('HS'):out.append('SYMMETRIC_ALGORITHM')
 for k,label in [('kid','KID_PRESENT'),('jku','JKU_PRESENT'),('jwk','EMBEDDED_JWK'),('x5u','X5U_PRESENT'),('crit','CRIT_PRESENT')]:
  if k in h:out.append(label)
 if 'kid' not in h:out.append('KID_MISSING')
 if h.get('typ') not in (None,'JWT','at+jwt'):out.append('UNUSUAL_TYP')
 return out
