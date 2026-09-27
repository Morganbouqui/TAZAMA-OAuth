from tazama_oauth.tokens.jwks import parse_jwks
class JWKSService:
 def __init__(self,transport):self.transport=transport
 async def fetch(self,url):
  if not self.transport.scope.allows_url(url):return {'url':url,'scope_status':'OUT_OF_SCOPE','request_status':'NOT_REQUESTED','keys':[]}
  r=await self.transport.request('GET',url)
  import json
  return {'url':url,'scope_status':'IN_SCOPE','request_status':'REQUESTED','keys':parse_jwks(json.loads(r.body))}
