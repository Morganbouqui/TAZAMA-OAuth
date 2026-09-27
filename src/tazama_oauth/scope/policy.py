import ipaddress
from urllib.parse import urlsplit
from tazama_oauth.scope.models import ScopeRule,ScopeKind,CallbackRule
from tazama_oauth.scope.normalize import normalize_host,normalize_url
from tazama_oauth.core.errors import ScopeDenied
class ScopePolicy:
    def __init__(self,rules=(),callbacks=()): self.rules=list(rules); self.callbacks=list(callbacks)
    @staticmethod
    def parse_rule(raw:str)->ScopeRule:
        s=raw.strip()
        if s.startswith("http://") or s.startswith("https://"): return ScopeRule(ScopeKind.URL_PREFIX,normalize_url(s))
        if s.startswith("*."): return ScopeRule(ScopeKind.WILDCARD_HOST,normalize_host(s[2:]))
        try:
            net=ipaddress.ip_network(s,strict=False)
            if "/" in s: return ScopeRule(ScopeKind.CIDR,str(net))
            return ScopeRule(ScopeKind.IP,str(net.network_address))
        except ValueError: return ScopeRule(ScopeKind.EXACT_HOST,normalize_host(s))
    def allows_url(self,url:str)->bool:
        try: nurl=normalize_url(url); p=urlsplit(nurl); host=normalize_host(p.hostname or "")
        except ValueError: return False
        for r in self.rules:
            if r.kind is ScopeKind.EXACT_HOST and host==r.value: return True
            if r.kind is ScopeKind.WILDCARD_HOST and host.endswith("."+r.value) and host!=r.value: return True
            if r.kind is ScopeKind.URL_PREFIX and (nurl==r.value or nurl.startswith(r.value.rstrip("/")+"/")): return True
            if r.kind is ScopeKind.IP and host==r.value: return True
            if r.kind is ScopeKind.CIDR:
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(r.value): return True
                except ValueError: pass
        return False
    def require_url(self,url:str)->None:
        if not self.allows_url(url): raise ScopeDenied(f"destination outside authorized assessment scope: {url}")
    def allows_callback(self,url:str)->bool:
        try: n=normalize_url(url)
        except ValueError:return False
        return any(n==normalize_url(c.url) for c in self.callbacks)
