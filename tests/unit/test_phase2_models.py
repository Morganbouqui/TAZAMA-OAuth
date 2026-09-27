import json
from tazama_oauth.oauth.relationships import RelationshipGraph,Relationship
from tazama_oauth.oauth.inventory import EndpointInventory
from tazama_oauth.oauth.models import EndpointObservation

def test_relationship_serialization():
 g=RelationshipGraph([{'id':'app','type':'Application'}],[Relationship('app','CLIENT_AUTHORIZES_AT','id',['e1'])]); assert json.loads(json.dumps(g.as_dict()))['relationships'][0]['relation']=='CLIENT_AUTHORIZES_AT'
def test_inventory_serialization():
 i=EndpointInventory([EndpointObservation('token','https://id/token','metadata','IN_SCOPE','metadata')]); assert json.loads(json.dumps(i.as_dict()))['endpoints'][0]['request_status']=='NOT_REQUESTED'
