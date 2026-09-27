import pytest
from tazama_oauth.core.safety import SafetyPolicy
from tazama_oauth.core.models import RiskLevel
from tazama_oauth.core.errors import RiskDenied
from tazama_oauth.plugins.base import PluginServices
class FakeTransport:
 def __init__(self): self.called=False
 async def request(self,*a,**k): self.called=True; return "ok"
def test_active_denied():
 with pytest.raises(RiskDenied): SafetyPolicy().require(RiskLevel.ACTIVE)
def test_active_allowed(): SafetyPolicy(active=True).require(RiskLevel.ACTIVE)
@pytest.mark.asyncio
async def test_plugin_service_gates_active():
 t=FakeTransport(); s=PluginServices(t,SafetyPolicy())
 with pytest.raises(RiskDenied): await s.request(RiskLevel.ACTIVE,"GET","https://x")
 assert not t.called
