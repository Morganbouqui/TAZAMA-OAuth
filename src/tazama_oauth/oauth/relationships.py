from dataclasses import dataclass,field,asdict
@dataclass(slots=True)
class Relationship:
    source:str; relation:str; target:str; evidence_ids:list[str]=field(default_factory=list)
@dataclass(slots=True)
class RelationshipGraph:
    entities:list[dict]=field(default_factory=list); relationships:list[Relationship]=field(default_factory=list); schema_version:int=1
    def as_dict(self): return {'schema_version':self.schema_version,'entities':self.entities,'relationships':[asdict(x) for x in self.relationships]}
