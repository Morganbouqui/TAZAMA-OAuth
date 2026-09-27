from tazama_oauth.core.models import RiskLevel
from tazama_oauth.core.safety import SafetyPolicy
from tazama_oauth.testing.mutation import mutate_url
from tazama_oauth.testing.differential import compare
from tazama_oauth.testing.models import TestOutcome
from tazama_oauth.testing.confidence import classify
class DifferentialTestEngine:
    def __init__(self,transport,safety:SafetyPolicy): self.transport=transport; self.safety=safety
    async def execute(self,baseline,mutation,*,dry_run=False,callback_required=False):
        self.safety.require(RiskLevel.ACTIVE)
        url=mutate_url(mutation.target,mutation)
        if callback_required and mutation.parameter=='redirect_uri':
            from urllib.parse import urlsplit,parse_qs
            cb=parse_qs(urlsplit(url).query).get('redirect_uri',[''])[0]
            if not self.transport.scope.allows_callback(cb): return TestOutcome(mutation,False,'BLOCKED_BY_SCOPE')
        if not self.transport.scope.allows_url(url): return TestOutcome(mutation,False,'BLOCKED_BY_SCOPE')
        if dry_run:return TestOutcome(mutation,False,'DRY_RUN')
        result=await self.transport.request(baseline.method,url)
        comp=compare(baseline,result); suspicious=(result.status<400 and not comp.oauth_error)
        return TestOutcome(mutation,True,comparison=comp,confidence=classify(suspicious_acceptance=suspicious))
