from dataclasses import dataclass,field
from tazama_oauth.evidence.models import RedirectHop
@dataclass(slots=True)
class HTTPResult:
    url:str; status:int; headers:dict[str,str]; body:str; redirect_chain:list[RedirectHop]=field(default_factory=list)
