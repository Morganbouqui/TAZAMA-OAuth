from dataclasses import dataclass, field, asdict
from enum import StrEnum

class FlowBasis(StrEnum):
    SUPPORTED='SUPPORTED'; OBSERVED='OBSERVED'; INFERRED='INFERRED'

@dataclass(slots=True)
class AuthorizationRequest:
    url:str
    client_id:str|None=None; redirect_uri:str|None=None; response_type:list[str]=field(default_factory=list)
    response_mode:str|None=None; scopes:list[str]=field(default_factory=list)
    state:str|None=None; nonce:str|None=None; code_challenge:str|None=None; code_challenge_method:str|None=None
    prompt:list[str]=field(default_factory=list); audience:list[str]=field(default_factory=list); resource:list[str]=field(default_factory=list)
    additional:dict[str,list[str]]=field(default_factory=dict); repeated:dict[str,list[str]]=field(default_factory=dict); evidence_ids:list[str]=field(default_factory=list)
    def as_dict(self): return asdict(self)

@dataclass(slots=True)
class EndpointObservation:
    type:str; url:str; source:str; scope_status:str; discovery_method:str; provider:str|None=None
    request_status:str='NOT_REQUESTED'; http_status:int|None=None; evidence_ids:list[str]=field(default_factory=list)
    def as_dict(self): return asdict(self)

@dataclass(slots=True)
class FlowObservation:
    flow:str; basis:FlowBasis; evidence:list[str]=field(default_factory=list)
    def as_dict(self): return asdict(self)
