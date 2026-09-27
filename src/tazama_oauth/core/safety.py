from dataclasses import dataclass
from tazama_oauth.core.models import RiskLevel
from tazama_oauth.core.errors import RiskDenied
@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    active: bool=False
    high_impact_confirmed: bool=False
    def require(self, risk:RiskLevel)->None:
        if risk is RiskLevel.ACTIVE and not self.active: raise RiskDenied("ACTIVE operation requires explicit --active authorization")
        if risk is RiskLevel.HIGH_IMPACT and not (self.active and self.high_impact_confirmed): raise RiskDenied("HIGH_IMPACT operation requires --active and explicit confirmation")
