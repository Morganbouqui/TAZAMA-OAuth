from dataclasses import dataclass,field,asdict
from enum import StrEnum
from uuid import uuid4
from tazama_oauth.core.models import RiskLevel,EvidenceState
class MutationKind(StrEnum):
    REMOVE_PARAMETER='REMOVE_PARAMETER'; EMPTY_PARAMETER='EMPTY_PARAMETER'; REPLACE_PARAMETER='REPLACE_PARAMETER'; DUPLICATE_PARAMETER='DUPLICATE_PARAMETER'; ALTER_CALLBACK='ALTER_CALLBACK'; ALTER_PKCE='ALTER_PKCE'
@dataclass(slots=True)
class TestMutation:
    test_type:str; parameter:str; mutation:MutationKind; target:str; expected_security_property:str; baseline_id:str
    original_state:str|None=None; replacement:str|None=None; risk_level:RiskLevel=RiskLevel.ACTIVE; mutation_id:str=field(default_factory=lambda:str(uuid4()))
    def as_dict(self): return asdict(self)
@dataclass(slots=True)
class DifferentialObservation:
    status_changed:bool; location_changed:bool; redirect_chain_changed:bool; body_hash_changed:bool; body_length_delta:int
    oauth_error:str|None=None; oauth_error_description:str|None=None; authorization_code_present:bool=False; token_like_present:bool=False
    def as_dict(self): return asdict(self)
@dataclass(slots=True)
class TestPlan:
    test_type:str; target:str; baseline_id:str; mutations:list[TestMutation]; blocked:list[TestMutation]=field(default_factory=list)
@dataclass(slots=True)
class TestOutcome:
    mutation:TestMutation; transmitted:bool; blocked_reason:str|None=None; evidence_id:str|None=None; comparison:DifferentialObservation|None=None; confidence:EvidenceState=EvidenceState.OBSERVED
