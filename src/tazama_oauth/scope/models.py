from dataclasses import dataclass
from enum import StrEnum
class ScopeKind(StrEnum): EXACT_HOST="exact_host"; WILDCARD_HOST="wildcard_host"; URL_PREFIX="url_prefix"; IP="ip"; CIDR="cidr"
@dataclass(frozen=True,slots=True)
class ScopeRule:
    kind:ScopeKind; value:str
@dataclass(frozen=True,slots=True)
class CallbackRule:
    url:str
