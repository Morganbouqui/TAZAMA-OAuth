from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from uuid import uuid4
SCHEMA_VERSION=1
@dataclass(slots=True)
class RedirectHop:
    url:str; status:int; location:str|None; followed:bool; scope_allowed:bool
@dataclass(slots=True)
class EvidenceRecord:
    target:str; module:str; request:dict; response:dict
    redirect_chain:list[RedirectHop]=field(default_factory=list)
    schema_version:int=SCHEMA_VERSION
    evidence_id:str=field(default_factory=lambda:str(uuid4()))
    timestamp:str=field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
    def as_dict(self): return asdict(self)
