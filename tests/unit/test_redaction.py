import json
from tazama_oauth.evidence.redaction import *
def test_url_query_redaction():
 s=redact_url("https://x.test/cb?code=secret123&state=ok"); assert "secret123" not in s and "state=ok" in s

def test_header_redaction():
 d=redact_headers({"Authorization":"Bearer secret123","Cookie":"sid=secret456","X":"ok"}); s=json.dumps(d); assert "secret123" not in s and "secret456" not in s and "ok" in s

def test_json_form_redaction():
 j=redact_body('{"access_token":"secret123","x":"ok"}',"application/json"); assert j["access_token"]["value"]=="[REDACTED]"
 f=redact_body("client_secret=secret456&x=ok","application/x-www-form-urlencoded"); assert f["client_secret"]["value"]=="[REDACTED]"

def test_fingerprint_stable(): assert fingerprint("same")==fingerprint("same") and fingerprint("same")!=fingerprint("other")
