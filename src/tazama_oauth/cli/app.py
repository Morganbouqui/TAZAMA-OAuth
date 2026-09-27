from pathlib import Path
import asyncio,json,sys,typer
from rich.console import Console
from rich.table import Table
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
from tazama_oauth.tokens.parser import decode
from tazama_oauth.tokens.claims import analyze_time,safe_claims
from tazama_oauth.tokens.compare import compare_tokens
from tazama_oauth.tokens.verify import verify_hmac
from tazama_oauth.tokens.observations import jose_observations
from tazama_oauth.oidc.validation import validate_id_token
app=typer.Typer(name='tazama-oauth',add_completion=False,help='TAZAMA-OAuth — independent, scope-aware OAuth/OIDC assessment foundation.',invoke_without_command=True)
scope_app=typer.Typer(help='Manage assessment scope.'); oidc_app=typer.Typer(help='OpenID Connect intelligence.'); test_app=typer.Typer(help='Controlled differential security tests.'); token_app=typer.Typer(help='Local token/JWT intelligence.')
for sub,name in [(scope_app,'scope'),(oidc_app,'oidc'),(test_app,'test'),(token_app,'token')]:app.add_typer(sub,name=name)
console=Console()
class Runtime: active=False; dry_run=False; project=Path('.')
runtime=Runtime()
def version_cb(value:bool):
 if value:console.print(f'tazama-oauth {__version__}');raise typer.Exit()
@app.callback()
def root(ctx:typer.Context,version:bool=typer.Option(False,'--version',callback=version_cb,is_eager=True,help='Show version and exit.'),active:bool=typer.Option(False,'--active'),dry_run:bool=typer.Option(False,'--dry-run'),project:Path=typer.Option(Path('.'),'--project')):
 runtime.active=active;runtime.dry_run=dry_run;runtime.project=project
 if ctx.invoked_subcommand is None and not version:run_interactive()
@app.command('init')
def init(path:Path=typer.Argument(Path('.')),name:str=typer.Option('default','--name')):console.print(f'Initialized: {init_workspace(path,name).root}')
@scope_app.command('add')
def scope_add(target:str):add_scope_rule(runtime.project,target);console.print(f'Added assessment scope: {target}')
@scope_app.command('add-callback')
def callback_add(url:str):add_callback(runtime.project,url);console.print(f'Added callback receive authorization: {url}')
@scope_app.command('check')
def scope_check(target:str):console.print('AUTHORIZED' if load_project_scope(runtime.project).allows_url(target) else 'DENIED')
def _service():return DiscoveryService(ControlledTransport(load_project_scope(runtime.project)))
@app.command('discover')
def discover(target:str):
 d=asyncio.run(_service().discover(target));console.print(f"OAuth detected: {d['oauth_detected']}");console.print(f"Authorization requests: {len(d['authorization_requests'])}");console.print(f"Endpoints/references: {len(d['endpoints'])}")
@app.command('map')
def map_flow(target:str):
 d=asyncio.run(_service().discover(target));flows=[f for r in d['authorization_requests'] for f in observed_flows(r)]
 for f in flows:console.print(f'{f.basis}: {f.flow}')
 if not flows:console.print('No observed flow identified.')
@app.command('analyze')
def analyze(target:str):
 for k,v in summarize(asyncio.run(_service().discover(target))).items():console.print(f'{k}: {v}')
@oidc_app.command('discover')
def oidc_discover(target:str):
 meta,endpoints,_=asyncio.run(_service().oidc_discover(target));console.print(f'Issuer: {meta.issuer or "not observed"}')
 for e in endpoints:console.print(f'{e.type}: {e.url} [{e.scope_status}/{e.request_status}]')
def _token_arg(token,file):
 if token:return token.strip()
 if file:return file.read_text(encoding='utf-8').strip()
 if not sys.stdin.isatty():return sys.stdin.read().strip()
 raise typer.BadParameter('provide TOKEN, --file, or stdin')
@token_app.command('inspect')
def token_inspect(token:str|None=typer.Argument(None),file:Path|None=typer.Option(None,'--file')):
 d=decode(_token_arg(token,file));t=Table('Field','Value');t.add_row('Token type',d.token_type.value);t.add_row('Segments',str(d.segments));t.add_row('State',d.state.value);t.add_row('Algorithm',str(d.header.get('alg')));t.add_row('Type',str(d.header.get('typ')));t.add_row('Key ID',str(d.header.get('kid')));console.print(t);console.print('Claims',safe_claims(d.claims));console.print('Time',analyze_time(d.claims));console.print('JOSE observations',jose_observations(d))
@token_app.command('compare')
def token_compare(token_a:str|None=typer.Argument(None),token_b:str|None=typer.Argument(None),file_a:Path|None=typer.Option(None,'--file-a'),file_b:Path|None=typer.Option(None,'--file-b')):
 if token_a is None and file_a:token_a=file_a.read_text().strip()
 if token_b is None and file_b:token_b=file_b.read_text().strip()
 if not token_a or not token_b:raise typer.BadParameter('provide two tokens or --file-a/--file-b')
 console.print_json(data=compare_tokens(token_a,token_b))
@token_app.command('verify')
def token_verify(token:str|None=typer.Argument(None),file:Path|None=typer.Option(None,'--file'),hmac_secret_file:Path|None=typer.Option(None,'--hmac-secret-file')):
 raw=_token_arg(token,file)
 if not hmac_secret_file:console.print('Signature: NOT_TESTED (supply trusted verification material)');return
 console.print_json(data=verify_hmac(raw,hmac_secret_file.read_bytes().strip()).as_dict())
@oidc_app.command('validate-id-token')
def validate_id(token:str|None=typer.Argument(None),file:Path|None=typer.Option(None,'--file'),issuer:str|None=typer.Option(None,'--issuer'),audience:str|None=typer.Option(None,'--audience'),nonce:str|None=typer.Option(None,'--nonce'),client_id:str|None=typer.Option(None,'--client-id'),leeway:int=typer.Option(0,'--leeway'),hmac_secret_file:Path|None=typer.Option(None,'--hmac-secret-file')):
 raw=_token_arg(token,file);secret=hmac_secret_file.read_bytes().strip() if hmac_secret_file else None
 sources={k:'explicit CLI' for k,v in {'issuer':issuer,'audience':audience,'nonce':nonce,'client_id':client_id}.items() if v is not None}
 console.print_json(data=validate_id_token(raw,hmac_secret=secret,issuer=issuer,audience=audience,nonce=nonce,client_id=client_id,leeway=leeway,sources=sources).as_dict())
def _plan(target,kind,baseline_id='planned',alternate_callback=None):return redirect_plan(target,baseline_id,alternate_callback) if kind=='redirect-uri' else {'state':state_plan,'pkce':pkce_plan}[kind](target,baseline_id)
async def _test(target,kind,alternate_callback=None):
 scope=load_project_scope(runtime.project);scope.require_url(target)
 if not runtime.active:
  p=_plan(target,kind,alternate_callback=alternate_callback);console.print('Risk: ACTIVE')
  for m in p.mutations:console.print(f'PLANNED {m.mutation}: {m.parameter}')
  console.print('Mutations not transmitted: --active not supplied');return
 transport=ControlledTransport(scope);r=await transport.request('GET',target);b=create_baseline('GET',target,{},None,r);p=_plan(target,kind,b.baseline_id,alternate_callback);e=DifferentialTestEngine(transport,SafetyPolicy(active=True))
 for m in p.mutations:
  o=await e.execute(b,m,dry_run=runtime.dry_run,callback_required=(kind=='redirect-uri'));console.print(f'{m.mutation}: {"SENT" if o.transmitted else o.blocked_reason} [{o.confidence}]')
@test_app.command('state')
def test_state(target:str):asyncio.run(_test(target,'state'))
@test_app.command('redirect-uri')
def test_redirect_uri(target:str,alternate_callback:str|None=typer.Option(None,'--alternate-callback')):asyncio.run(_test(target,'redirect-uri',alternate_callback))
@test_app.command('pkce')
def test_pkce(target:str):asyncio.run(_test(target,'pkce'))
def main():app()
