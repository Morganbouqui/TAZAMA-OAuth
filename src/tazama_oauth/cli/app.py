from pathlib import Path
import asyncio,typer
from rich.console import Console
from tazama_oauth import __version__
from tazama_oauth.cli.interactive import run_interactive
from tazama_oauth.workspace.manager import init_workspace
from tazama_oauth.scope.policy import ScopePolicy
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.oauth.discovery.service import DiscoveryService
from tazama_oauth.oauth.flow.mapper import observed_flows
from tazama_oauth.analysis.passive import summarize
app=typer.Typer(name='tazama-oauth',add_completion=False,help='TAZAMA-OAuth — independent, scope-aware OAuth/OIDC assessment foundation.',invoke_without_command=True)
scope_app=typer.Typer(help='Manage assessment scope.'); oidc_app=typer.Typer(help='OpenID Connect intelligence.')
app.add_typer(scope_app,name='scope'); app.add_typer(oidc_app,name='oidc'); console=Console()
def version_cb(value:bool):
    if value: console.print(f'tazama-oauth {__version__}'); raise typer.Exit()
@app.callback()
def root(ctx:typer.Context,version:bool=typer.Option(False,'--version',callback=version_cb,is_eager=True,help='Show version and exit.'),active:bool=typer.Option(False,'--active',help='Authorize ACTIVE-risk operations for this invocation.')):
    if ctx.invoked_subcommand is None and not version: run_interactive()
@app.command('init')
def init(path:Path=typer.Argument(Path('.')),name:str=typer.Option('default','--name')):
    ws=init_workspace(path,name); console.print(f'Initialized: {ws.root}')
@scope_app.command('check')
def scope_check(target:str,rule:list[str]=typer.Option([],'--rule')):
    p=ScopePolicy([ScopePolicy.parse_rule(x) for x in rule]); console.print('AUTHORIZED' if p.allows_url(target) else 'DENIED')
def _service(target:str):
    from urllib.parse import urlsplit
    host=urlsplit(target).hostname
    if not host: raise typer.BadParameter('target must be a complete http(s) URL')
    return DiscoveryService(ControlledTransport(ScopePolicy([ScopePolicy.parse_rule(host)])))
@app.command('discover')
def discover(target:str):
    '''Passively discover OAuth/OIDC indicators on an authorized target.'''
    d=asyncio.run(_service(target).discover(target)); console.print(f"OAuth detected: {d['oauth_detected']}"); console.print(f"Authorization requests: {len(d['authorization_requests'])}"); console.print(f"Endpoints/references: {len(d['endpoints'])}")
@app.command('map')
def map_flow(target:str):
    '''Map observed OAuth/OIDC flows from passive evidence.'''
    d=asyncio.run(_service(target).discover(target)); flows=[f for r in d['authorization_requests'] for f in observed_flows(r)]
    for f in flows: console.print(f'{f.basis}: {f.flow}')
    if not flows: console.print('No observed flow identified.')
@app.command('analyze')
def analyze(target:str):
    '''Summarize passive OAuth/OIDC intelligence without vulnerability claims.'''
    d=asyncio.run(_service(target).discover(target)); s=summarize(d)
    for k,v in s.items(): console.print(f'{k}: {v}')
@oidc_app.command('discover')
def oidc_discover(target:str):
    '''Retrieve and parse in-scope OIDC discovery metadata.'''
    meta,endpoints,_=asyncio.run(_service(target).oidc_discover(target)); console.print(f'Issuer: {meta.issuer or "not observed"}')
    for e in endpoints: console.print(f'{e.type}: {e.url} [{e.scope_status}/{e.request_status}]')
def main(): app()
