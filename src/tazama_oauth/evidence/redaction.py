import hashlib,json,re
from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
SECRET_KEYS={"access_token","refresh_token","id_token","code","client_secret","password","api_key","apikey","token","authorization","cookie","set-cookie","state","nonce"}
def fingerprint(value:str)->str: return "SHA256:"+hashlib.sha256(value.encode()).hexdigest()
def _secret(value:str)->dict: return {"value":"[REDACTED]","fingerprint":fingerprint(value)}
def redact_url(url:str):
    p=urlsplit(url); out=[]
    for k,v in parse_qsl(p.query,keep_blank_values=True): out.append((k,"[REDACTED]" if k.lower() in SECRET_KEYS else v))
    return urlunsplit((p.scheme,p.netloc,p.path,urlencode(out),p.fragment))
def redact_headers(headers:dict[str,str]):
    out={}
    for k,v in headers.items():
        lk=k.lower()
        if lk in {"authorization","cookie","set-cookie","x-api-key"}: out[k]=_secret(v)
        else: out[k]=v
    return out
def redact_mapping(obj):
    if isinstance(obj,dict): return {k:(_secret(str(v)) if k.lower() in SECRET_KEYS else redact_mapping(v)) for k,v in obj.items()}
    if isinstance(obj,list): return [redact_mapping(v) for v in obj]
    return obj
def redact_body(body,content_type:str=""):
    if body is None:return None
    if isinstance(body,(dict,list)): return redact_mapping(body)
    s=body.decode(errors="replace") if isinstance(body,bytes) else str(body)
    if "json" in content_type:
        try:return redact_mapping(json.loads(s))
        except json.JSONDecodeError:return s
    if "x-www-form-urlencoded" in content_type:
        return {k:(_secret(v) if k.lower() in SECRET_KEYS else v) for k,v in parse_qsl(s,keep_blank_values=True)}
    for key in SECRET_KEYS: s=re.sub(rf"(?i)({re.escape(key)}\s*[=:]\s*)([^&\s]+)",rf"\1[REDACTED]",s)
    return s
