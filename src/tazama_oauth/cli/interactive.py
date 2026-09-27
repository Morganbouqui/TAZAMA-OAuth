from rich.console import Console
from rich.panel import Panel
console=Console()
def run_interactive()->None:
    console.print(Panel.fit("[bold]TAZAMA-OAuth[/bold]\nOAuth / OIDC Security Assessment\n\nPhase 1 foundation — protocol testing is not implemented yet."))
    console.print("[1] Project / Scope\n[2] Evidence\n[3] Settings\n[0] Exit")
