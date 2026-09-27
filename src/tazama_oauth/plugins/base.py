from dataclasses import dataclass
from typing import Protocol
from tazama_oauth.core.models import RiskLevel
from tazama_oauth.core.safety import SafetyPolicy
from tazama_oauth.http.transport import ControlledTransport
@dataclass(frozen=True,slots=True)
class PluginServices:
    transport:ControlledTransport
    safety:SafetyPolicy
    async def request(self,risk:RiskLevel,*args,**kwargs):
        self.safety.require(risk)
        return await self.transport.request(*args,**kwargs)
class OAuthModule(Protocol):
    name:str; risk_level:RiskLevel
    async def execute(self,services:PluginServices): ...
