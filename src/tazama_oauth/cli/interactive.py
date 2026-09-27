from rich.console import Console
from rich.panel import Panel
console=Console()
def run_interactive()->None:
    console.print(Panel.fit('[bold]TAZAMA-OAuth[/bold]\nOAuth / OIDC Security Assessment\n\nPhase 2 — passive protocol intelligence.'))
    console.print('[1] Project / Scope\n[2] OAuth Discovery\n[3] OIDC Discovery\n[4] Authorization Flow Mapper\n[5] Evidence\n[6] Settings\n[0] Exit')
