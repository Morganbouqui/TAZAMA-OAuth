import ast
from pathlib import Path

def test_network_library_imports_are_confined_to_transport():
 root=Path(__file__).parents[2]/"src"/"tazama_oauth"
 offenders=[]
 for path in root.rglob("*.py"):
  rel=path.relative_to(root).as_posix()
  if rel=="http/transport.py": continue
  tree=ast.parse(path.read_text(encoding="utf-8"))
  for node in ast.walk(tree):
   if isinstance(node,ast.Import):
    if any(a.name in {"httpx","requests","urllib.request","aiohttp","socket"} for a in node.names): offenders.append(rel)
   elif isinstance(node,ast.ImportFrom) and node.module in {"httpx","requests","urllib.request","aiohttp","socket"}: offenders.append(rel)
 assert offenders==[]
