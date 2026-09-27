from typer.testing import CliRunner
from tazama_oauth.cli.app import app
r=CliRunner()
def test_help(): assert r.invoke(app,["--help"]).exit_code==0 and "TAZAMA" in r.invoke(app,["--help"]).stdout
def test_version():
 x=r.invoke(app,["--version"]); assert x.exit_code==0 and "0.1.0" in x.stdout
