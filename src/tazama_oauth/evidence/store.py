from pathlib import Path
from tazama_oauth.core.config import atomic_json_write
from tazama_oauth.evidence.models import EvidenceRecord
from tazama_oauth.evidence.redaction import redact_url,redact_headers,redact_body
class EvidenceStore:
    def __init__(self,root:Path): self.root=root; self.root.mkdir(parents=True,exist_ok=True)
    def save(self,record:EvidenceRecord)->Path:
        d=record.as_dict(); req=d["request"]; resp=d["response"]
        if "url" in req:req["url"]=redact_url(req["url"])
        req["headers"]=redact_headers(req.get("headers",{})); req["body"]=redact_body(req.get("body"),req.get("content_type",""))
        resp["headers"]=redact_headers(resp.get("headers",{})); resp["body"]=redact_body(resp.get("body"),resp.get("content_type",""))
        for h in d.get("redirect_chain",[]):
            h["url"]=redact_url(h["url"])
            if h.get("location"):h["location"]=redact_url(h["location"])
        path=self.root/f"{record.evidence_id}.json"; atomic_json_write(path,d); return path
