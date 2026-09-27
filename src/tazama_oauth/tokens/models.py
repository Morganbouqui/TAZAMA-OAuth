from dataclasses import dataclass,field,asdict
from enum import StrEnum
class TokenType(StrEnum): OPAQUE='OPAQUE'; JWT='JWT'; JWS='JWS'; JWE_LIKE='JWE_LIKE'; UNKNOWN='UNKNOWN'
class VerificationState(StrEnum): DECODED='DECODED'; STRUCTURALLY_VALID='STRUCTURALLY_VALID'; SIGNATURE_VERIFIED='SIGNATURE_VERIFIED'; CLAIMS_VALIDATED='CLAIMS_VALIDATED'; SERVER_ACCEPTANCE_OBSERVED='SERVER_ACCEPTANCE_OBSERVED'; REJECTED='REJECTED'; UNVERIFIED='UNVERIFIED'
@dataclass(slots=True)
class DecodedToken:
 token_type:TokenType; segments:int; header:dict=field(default_factory=dict); claims:dict=field(default_factory=dict); signature_present:bool=False; state:VerificationState=VerificationState.UNVERIFIED; fingerprint:str=''
 def as_dict(self): return asdict(self)
@dataclass(slots=True)
class VerificationResult:
 algorithm:str|None; key_source:str; kid:str|None; key_selected:str|None; signature:str; claims:str='NOT_TESTED'; details:dict=field(default_factory=dict)
 def as_dict(self): return asdict(self)
