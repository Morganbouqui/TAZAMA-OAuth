import base64,json
from typer.testing import CliRunner
from tazama_oauth.cli.app import app
from tazama_oauth.tokens.compare import compare_tokens
r=CliRunner()
def e(x):return base64.urlsafe_b64encode(json.dumps(x).encode()).rstrip(b'=').decode()
def t(sub):return f"{e({'alg':'RS256','typ':'JWT','kid':'k'})}.{e({'sub':sub,'aud':'a','exp':1})}.sig"
def test_compare_fingerprints_subject():
 x=compare_tokens(t('secret-a'),t('secret-b'));assert 'secret-a' not in str(x) and x['claims']['sub_fingerprint'][0].startswith('SHA256:')
def test_phase4_help():
 for args in (['token','inspect','--help'],['token','verify','--help'],['token','compare','--help'],['oidc','validate-id-token','--help']):
  z=r.invoke(app,args);assert z.exit_code==0,(args,z.stdout,z.exception)
def test_inspect_local():
 z=r.invoke(app,['token','inspect',t('s')]);assert z.exit_code==0 and 'JWT' in z.stdout
