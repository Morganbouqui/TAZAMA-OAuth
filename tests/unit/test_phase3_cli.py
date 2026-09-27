from typer.testing import CliRunner
from tazama_oauth.cli.app import app
r=CliRunner()
def test_phase3_help():
 for args in (['test','state','--help'],['test','redirect-uri','--help'],['test','pkce','--help']):
  x=r.invoke(app,args); assert x.exit_code==0,(args,x.stdout,x.exception)
