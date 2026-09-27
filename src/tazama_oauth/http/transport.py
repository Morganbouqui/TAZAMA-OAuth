import asyncio,time
from urllib.parse import urljoin
import httpx
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.evidence.models import RedirectHop
from tazama_oauth.http.models import HTTPResult
class ControlledTransport:
    """Only network gateway exposed to assessment modules/plugins."""
    def __init__(self,scope:ScopePolicy,*,timeout=10.0,proxy=None,verify=True,max_redirects=10,concurrency=5,rate_per_second=5.0,transport=None):
        self.scope=scope; self.timeout=timeout; self.proxy=proxy; self.verify=verify; self.max_redirects=max_redirects
        self._sem=asyncio.Semaphore(concurrency); self._rate=max(rate_per_second,0.01); self._last=0.0; self._transport=transport
    async def _pace(self):
        wait=max(0,(1/self._rate)-(time.monotonic()-self._last))
        if wait: await asyncio.sleep(wait)
        self._last=time.monotonic()
    async def request(self,method:str,url:str,*,headers=None,content=None,dry_run=False)->HTTPResult:
        self.scope.require_url(url)  # invariant: before client/network construction
        if dry_run:return HTTPResult(url,0,{},"",[])
        chain=[]; current=url
        async with self._sem:
            async with httpx.AsyncClient(timeout=self.timeout,proxy=self.proxy,verify=self.verify,follow_redirects=False,transport=self._transport) as client:
                for _ in range(self.max_redirects+1):
                    self.scope.require_url(current); await self._pace()
                    response=await client.request(method,current,headers=headers,content=content)
                    loc=response.headers.get("location")
                    if response.is_redirect and loc:
                        nxt=urljoin(str(response.url),loc); allowed=self.scope.allows_url(nxt)
                        chain.append(RedirectHop(str(response.url),response.status_code,nxt,allowed,allowed))
                        if not allowed:
                            return HTTPResult(str(response.url),response.status_code,dict(response.headers),response.text,chain)
                        current=nxt; method="GET" if response.status_code in {301,302,303} else method; content=None
                        continue
                    return HTTPResult(str(response.url),response.status_code,dict(response.headers),response.text,chain)
        raise httpx.TooManyRedirects("redirect limit exceeded")
