from dataclasses import dataclass
from pathlib import Path
from tazama_oauth.core.config import AppConfig, atomic_json_write, save_config
SCHEMA_VERSION=1
@dataclass(frozen=True,slots=True)
class Workspace:
    root:Path
    @property
    def evidence(self): return self.root/"evidence"
    @property
    def reports(self): return self.root/"reports"
    @property
    def logs(self): return self.root/"logs"

def init_workspace(base:Path, project_name:str="default")->Workspace:
    root=base/".tazama_oauth"
    for d in (root,root/"evidence",root/"reports",root/"logs",root/"observations",root/"findings"): d.mkdir(parents=True,exist_ok=True)
    if not (root/"config.json").exists(): save_config(root/"config.json",AppConfig())
    if not (root/"project.json").exists(): atomic_json_write(root/"project.json",{"schema_version":SCHEMA_VERSION,"name":project_name})
    if not (root/"scope.json").exists(): atomic_json_write(root/"scope.json",{"schema_version":SCHEMA_VERSION,"rules":[],"callbacks":[]})
    if not (root/"state.json").exists(): atomic_json_write(root/"state.json",{"schema_version":SCHEMA_VERSION,"phase":1})
    return Workspace(root)
