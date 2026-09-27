from pathlib import Path
import typer
from rich.console import Console
from tazama_oauth import __version__
from tazama_oauth.cli.interactive import run_interactive
from tazama_oauth.workspace.manager import init_workspace
from tazama_oauth.scope.policy import ScopePolicy
app=typer.Typer(name="tazama-oauth", add_completion=False,help="TAZAMA-OAuth — independent, scope-aware OAuth/OIDC assessment foundation.",invoke_without_command=True)
scope_app=typer.Typer(help="Manage assessment scope.")
app.add_typer(scope_app,name="scope")
console=Console()
def version_cb(value:bool):
    if value:
        console.print(f"tazama-oauth {__version__}"); raise typer.Exit()
@app.callback()
def root(ctx:typer.Context,version:bool=typer.Option(False,"--version",callback=version_cb,is_eager=True,help="Show version and exit."),active:bool=typer.Option(False,"--active",help="Authorize ACTIVE-risk operations for this invocation.")):
    if ctx.invoked_subcommand is None and not version: run_interactive()
@app.command("init")
def init(path:Path=typer.Argument(Path(".")),name:str=typer.Option("default","--name")):
    ws=init_workspace(path,name); console.print(f"Initialized: {ws.root}")
@scope_app.command("check")
def scope_check(target:str,rule:list[str]=typer.Option([],"--rule")):
    p=ScopePolicy([ScopePolicy.parse_rule(x) for x in rule]); console.print("AUTHORIZED" if p.allows_url(target) else "DENIED")
def main(): app()
