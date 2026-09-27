from tazama_oauth.tokens.parser import decode
from tazama_oauth.tokens.claims import safe_claims
def compare_tokens(a,b):
 x,y=decode(a),decode(b); ax=safe_claims(x.claims); by=safe_claims(y.claims)
 fields=['iss','aud','scope','roles','permissions','exp','iat','nbf','azp','sub_fingerprint']
 return {'type':[x.token_type,y.token_type],'alg':[x.header.get('alg'),y.header.get('alg')],'typ':[x.header.get('typ'),y.header.get('typ')],'kid':[x.header.get('kid'),y.header.get('kid')],'signature_length':[len(a.split('.')[-1]),len(b.split('.')[-1])],'nonce_present':['nonce' in x.claims,'nonce' in y.claims],'claim_names':[sorted(x.claims),sorted(y.claims)],'claims':{f:[ax.get(f),by.get(f)] for f in fields}}
