from typer.testing import CliRunner
from tazama_oauth.cli.app import app
r=CliRunner()
def test_phase2_command_help():
 for args in (['discover','--help'],['map','--help'],['analyze','--help'],['oidc','discover','--help']):
  x=r.invoke(app,args); assert x.exit_code==0, (args,x.stdout,x.exception)
