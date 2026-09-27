from dataclasses import dataclass, asdict
from pathlib import Path
import json, os, tempfile
SCHEMA_VERSION=1
@dataclass(slots=True)
class AppConfig:
    schema_version:int=SCHEMA_VERSION
    timeout:float=10.0
    max_redirects:int=10
    concurrency:int=5
    rate_per_second:float=5.0
    verify_tls:bool=True
    proxy:str|None=None

def atomic_json_write(path:Path, data:dict)->None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(data,f,indent=2,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def save_config(path:Path, cfg:AppConfig)->None: atomic_json_write(path,asdict(cfg))
def load_config(path:Path)->AppConfig:
    return AppConfig(**json.loads(path.read_text(encoding="utf-8")))
