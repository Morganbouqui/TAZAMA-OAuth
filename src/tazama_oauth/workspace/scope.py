import json
from pathlib import Path
from tazama_oauth.scope.models import CallbackRule
from tazama_oauth.scope.policy import ScopePolicy

def load_project_scope(base:Path)->ScopePolicy:
    path=base/'.tazama_oauth'/'scope.json'
    if not path.exists(): return ScopePolicy([])
    data=json.loads(path.read_text(encoding='utf-8'))
    rules=[ScopePolicy.parse_rule(x) for x in data.get('rules',[])]
    callbacks=[CallbackRule(x) for x in data.get('callbacks',[])]
    return ScopePolicy(rules,callbacks)

def add_scope_rule(base:Path, raw:str)->None:
    from tazama_oauth.core.config import atomic_json_write
    path=base/'.tazama_oauth'/'scope.json'
    if not path.exists(): raise FileNotFoundError('initialize a project first')
    data=json.loads(path.read_text(encoding='utf-8')); ScopePolicy.parse_rule(raw)
    if raw not in data['rules']: data['rules'].append(raw)
    atomic_json_write(path,data)

def add_callback(base:Path, url:str)->None:
    from tazama_oauth.core.config import atomic_json_write
    path=base/'.tazama_oauth'/'scope.json'
    if not path.exists(): raise FileNotFoundError('initialize a project first')
    data=json.loads(path.read_text(encoding='utf-8')); CallbackRule(url)
    if url not in data['callbacks']: data['callbacks'].append(url)
    atomic_json_write(path,data)
