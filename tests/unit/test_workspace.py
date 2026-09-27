import json
from tazama_oauth.workspace.manager import init_workspace
from tazama_oauth.core.config import atomic_json_write
def test_workspace_and_schema(tmp_path):
 ws=init_workspace(tmp_path,"ACME")
 for n in ["config.json","project.json","scope.json","state.json"]:
  d=json.loads((ws.root/n).read_text()); assert d["schema_version"]==1
 assert ws.evidence.is_dir()
def test_atomic_write(tmp_path):
 p=tmp_path/"x.json"; atomic_json_write(p,{"schema_version":1,"x":2}); assert json.loads(p.read_text())["x"]==2; assert not list(tmp_path.glob("*.tmp"))
