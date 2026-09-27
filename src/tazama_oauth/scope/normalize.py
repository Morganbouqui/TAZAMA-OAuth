import ipaddress
from urllib.parse import urlsplit,urlunsplit

def normalize_host(host:str)->str:
    h=host.strip().rstrip(".")
    if h.startswith("[") and h.endswith("]"): h=h[1:-1]
    try: return str(ipaddress.ip_address(h))
    except ValueError: return h.encode("idna").decode("ascii").lower()

def normalize_url(url:str)->str:
    p=urlsplit(url)
    if p.scheme.lower() not in {"http","https"} or not p.hostname: raise ValueError("complete http(s) URL required")
    host=normalize_host(p.hostname)
    display_host=f"[{host}]" if ":" in host else host
    port=p.port
    if port and not ((p.scheme.lower()=="http" and port==80) or (p.scheme.lower()=="https" and port==443)): display_host+=f":{port}"
    path=p.path or "/"
    return urlunsplit((p.scheme.lower(),display_host,path,p.query,""))
