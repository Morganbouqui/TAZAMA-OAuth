from pathlib import Path
import asyncio,typer
from rich.console import Console
from tazama_oauth import __version__
from tazama_oauth.cli.interactive import run_interactive
from tazama_oauth.workspace.manager import init_workspace
from tazama_oauth.workspace.scope import load_project_scope,add_scope_rule,add_callback
from tazama_oauth.http.transport import ControlledTransport
from tazama_oauth.oauth.discovery.service import DiscoveryService
from tazama_oauth.oauth.flow.mapper import observed_flows
from tazama_oauth.analysis.passive import summarize
from tazama_oauth.core.safety import SafetyPolicy
from tazama_oauth.testing.baseline import create_baseline
from tazama_oauth.testing.engine import DifferentialTestEngine
from tazama_oauth.testing.plans import state_plan,redirect_plan,pkce_plan
app=typer.Typer(name='tazama-oauth',add_completion=False,help='TAZAMA-OAuth — independent, scope-aware OAuth/OIDC assessment foundation.',invoke_without_command=True)
scope_app=typer.Typer(help='Manage assessment scope.'); oidc_app=typer.Typer(help='OpenID Connect intelligence.'); test_app=typer.Typer(help='Controlled differential security tests.')
app.add_typer(scope_app,name='scope'); app.add_typer(oidc_app,name='oidc'); app.add_typer(test_app,name='test'); console=Console()
class Runtime: active=False; dry_run=False; project=Path('.')
runtime=Runtime()
def version_cb(value:bool):
    if value: console.print(f'tazama-oauth {__version__}'); raise typer.Exit()
@app.callback()
def root(ctx:typer.Context,version:bool=typer.Option(False,'--version',callback=version_cb,is_eager=True,help='Show version and exit.'),active:bool=typer.Option(False,'--active',help='Authorize ACTIVE-risk operations for this invocation.'),dry_run:bool=typer.Option(False,'--dry-run',help='Plan operations without transmitting active mutations.'),project:Path=typer.Option(Path('.'),'--project',help='Project directory containing .tazama_oauth.')):
    runtime.active=active; runtime.dry_run=dry_run; runtime.project=project
    if ctx.invoked_subcommand is None and not version: run_interactive()
@app.command('init')
def init(path:Path=typer.Argument(Path('.')),name:str=typer.Option('default','--name')):
    ws=init_workspace(path,name); console.print(f'Initialized: {ws.root}')
@scope_app.command('add')
def scope_add(target:str): add_scope_rule(runtime.project,target); console.print(f'Added assessment scope: {target}')
@scope_app.command('add-callback')
def callback_add(url:str): add_callback(runtime.project,url); console.print(f'Added callback receive authorization: {url}')
@scope_app.command('check')
def scope_check(target:str):
    p=load_project_scope(runtime.project); console.print('AUTHORIZED' if p.allows_url(target) else 'DENIED')
def _service(): return DiscoveryService(ControlledTransport(load_project_scope(runtime.project)))
@app.command('discover')
def discover(target:str):
    '''Passively discover OAuth/OIDC indicators on an explicitly scoped target.'''
    d=asyncio.run(_service().discover(target)); console.print(f"OAuth detected: {d['oauth_detected']}"); console.print(f"Authorization requests: {len(d['authorization_requests'])}"); console.print(f"Endpoints/references: {len(d['endpoints'])}")
@app.command('map')
def map_flow(target:str):
    '''Map observed OAuth/OIDC flows from passive evidence.'''
    d=asyncio.run(_service().discover(target)); flows=[f for r in d['authorization_requests'] for f in observed_flows(r)]
    for f in flows: console.print(f'{f.basis}: {f.flow}')
    if not flows: console.print('No observed flow identified.')
@app.command('analyze')
def analyze(target:str):
    '''Summarize passive OAuth/OIDC intelligence without vulnerability claims.'''
    d=asyncio.run(_service().discover(target)); s=summarize(d)
    for k,v in s.items(): console.print(f'{k}: {v}')
@oidc_app.command('discover')
def oidc_discover(target:str):
    '''Retrieve and parse in-scope OIDC discovery metadata.'''
    meta,endpoints,_=asyncio.run(_service().oidc_discover(target)); console.print(f'Issuer: {meta.issuer or "not observed"}')
    for e in endpoints: console.print(f'{e.type}: {e.url} [{e.scope_status}/{e.request_status}]')
def _plan(target,kind,baseline_id='planned',alternate_callback=None):
    return redirect_plan(target,baseline_id,alternate_callback) if kind=='redirect-uri' else {'state':state_plan,'pkce':pkce_plan}[kind](target,baseline_id)
async def _test(target,kind,alternate_callback=None):
    scope=load_project_scope(runtime.project); scope.require_url(target)
    if not runtime.active:
        p=_plan(target,kind,alternate_callback=alternate_callback); console.print('Risk: ACTIVE')
        for m in p.mutations:
            status='BLOCKED_BY_SCOPE' if kind=='redirect-uri' and m.replacement and not scope.allows_callback(m.replacement) else 'PLANNED'
            console.print(f'{status} {m.mutation}: {m.parameter}')
        console.print('Mutations not transmitted: --active not supplied'); return
    transport=ControlledTransport(scope)
    baseline_result=await transport.request('GET',target); baseline=create_baseline('GET',target,{},None,baseline_result); p=_plan(target,kind,baseline.baseline_id,alternate_callback)
    console.print(f'Baseline: {baseline.baseline_id}'); console.print('Risk: ACTIVE')
    engine=DifferentialTestEngine(transport,SafetyPolicy(active=True))
    for m in p.mutations:
        o=await engine.execute(baseline,m,dry_run=runtime.dry_run,callback_required=(kind=='redirect-uri'))
        console.print(f'{m.mutation}: {"SENT" if o.transmitted else o.blocked_reason} [{o.confidence}]')
@test_app.command('state')
def test_state(target:str): '''Plan or execute controlled state-binding mutations.'''; asyncio.run(_test(target,'state'))
@test_app.command('redirect-uri')
def test_redirect_uri(target:str,alternate_callback:str|None=typer.Option(None,'--alternate-callback')): '''Plan or execute callback-validation mutations.'''; asyncio.run(_test(target,'redirect-uri',alternate_callback))
@test_app.command('pkce')
def test_pkce(target:str): '''Plan or execute controlled PKCE mutations.'''; asyncio.run(_test(target,'pkce'))
def main(): app()
