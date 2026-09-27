from dataclasses import dataclass,field
from tazama_oauth.oauth.models import EndpointObservation
@dataclass(slots=True)
class EndpointInventory:
    endpoints:list[EndpointObservation]=field(default_factory=list); schema_version:int=1
    def as_dict(self): return {'schema_version':self.schema_version,'endpoints':[x.as_dict() for x in self.endpoints]}
