import pytest
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.scope.models import CallbackRule
@pytest.mark.parametrize("rule,url,allowed",[
("example.com","https://example.com/",True),("example.com","https://sub.example.com/",False),
("*.example.com","https://a.example.com/",True),("*.example.com","https://example.com/",False),
("https://example.com/api","https://example.com/api/v1",True),("https://example.com/api","https://example.com/other",False),
("127.0.0.1","http://127.0.0.1/",True),("2001:db8::1","http://[2001:db8::1]/",True),
("10.0.0.0/8","http://10.2.3.4/",True),("2001:db8::/32","http://[2001:db8::5]/",True),
("EXAMPLE.COM.","https://example.com:443/",True),("bücher.example","https://xn--bcher-kva.example/",True),
])
def test_scope(rule,url,allowed): assert ScopePolicy([ScopePolicy.parse_rule(rule)]).allows_url(url) is allowed

def test_default_ports_normalize():
 p=ScopePolicy([ScopePolicy.parse_rule("https://example.com:443/api")]); assert p.allows_url("https://example.com/api/x")

def test_callback_is_separate():
 p=ScopePolicy([], [CallbackRule("https://callback.example/cb")])
 assert p.allows_callback("https://callback.example:443/cb")
 assert not p.allows_url("https://callback.example/cb")
 assert not p.allows_callback("https://callback.example/other")
