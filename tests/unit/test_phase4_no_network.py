import ast
from pathlib import Path
def test_local_token_modules_have_no_network_imports():
 root=Path(__file__).parents[2]/'src'/'tazama_oauth'/'tokens'
 for p in root.glob('*.py'):
  if p.name=='service.py':continue
  tree=ast.parse(p.read_text())
  for n in ast.walk(tree):
   if isinstance(n,(ast.Import,ast.ImportFrom)):
    names=[x.name for x in n.names] if isinstance(n,ast.Import) else [n.module or '']
    assert not any(x.startswith(('httpx','requests','aiohttp','urllib.request','socket')) for x in names),(p,names)
