import typer
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from typing import Optional

# Importing our modules
from cloudsec_guard.core.engine import SecurityEngine
from cloudsec_guard.ai.gemini_client import GeminiRemediationAgent
from cloudsec_guard.utils.file_handler import read_file_securely

app = typer.Typer(
    name="cloudsec-guard",
    help="CloudSec-Guard: Production-Grade Cloud & Container Security Auditor.",
    add_completion=False
)
console = Console()

@app.command()
def scan(
    file_path: str = typer.Argument(..., help="Path to the file to scan (Dockerfile, K8s YAML, etc.)"),
    file_type: Optional[str] = typer.Option(None, "--type", "-t", help="Force file type: 'docker' or 'yaml'"),
    use_ai: bool = typer.Option(False, "--ai", help="Use Gemini AI for contextual analysis and code fixing")
):
    """
    Scans a configuration file for misconfigurations and security flaws.
    """
    console.print(Panel.fit("[bold blue]🛡️ CloudSec-Guard[/bold blue] - Infrastructure Security Auditor", border_style="blue"))
    
    target_path = Path(file_path)
    
    if not file_type:
        if target_path.name.lower() == "dockerfile" or target_path.suffix == ".dockerfile":
            file_type = "docker"
        elif target_path.suffix in [".yaml", ".yml"]:
            file_type = "yaml"
        else:
            console.print(f"[bold red][ERROR][/bold red] Cannot infer file type for '{file_path}'. Please specify using --type.")
            raise typer.Exit(code=1)
            
    engine = SecurityEngine()
    
    with console.status(f"[bold cyan]Scanning {file_type.upper()} file securely...[/bold cyan]", spinner="dots"):
        findings = engine.run_scan(file_path, file_type)

    if findings is None:
        console.print(f"[bold red][ERROR][/bold red] Scan failed. Check the logs for parsing errors.")
        raise typer.Exit(code=1)

    if not findings:
        console.print("[bold green]✅ No security vulnerabilities found. Your config is rock solid![/bold green]")
        raise typer.Exit(code=0)

    # ---------------------------------------------------------
    # Render Security Report
    # ---------------------------------------------------------
    console.print(f"\n[bold red]⚠️ Found {len(findings)} Security Issues in {target_path.name}:[/bold red]\n")

    table = Table(show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("ID", style="dim", width=15)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Vulnerability & Remediation")

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 4))

    for flaw in findings:
        sev = flaw.get("severity", "INFO")
        if sev == "HIGH":
            sev_styled = f"[bold white on red] {sev} [/bold white on red]"
        elif sev == "MEDIUM":
            sev_styled = f"[bold black on yellow] {sev} [/bold black on yellow]"
        elif sev == "LOW":
            sev_styled = f"[bold white on blue] {sev} [/bold white on blue]"
        else:
            sev_styled = f"[bold white on cyan] {sev} [/bold white on cyan]"

        details = (
            f"[bold]{flaw.get('title', 'Unknown Issue')}[/bold]\n"
            f"[dim]{flaw.get('description', '')}[/dim]\n"
            f"[bold green]💡 Fix:[/bold green] {flaw.get('remediation', '')}"
        )

        table.add_row(flaw.get("id", "N/A"), sev_styled, str(flaw.get("line", "?")), details)

    console.print(table)

    # ---------------------------------------------------------
    # Gemini AI Remediation
    # ---------------------------------------------------------
    if use_ai:
        console.print("\n[bold cyan]🧠 Initializing Gemini AI for contextual remediation...[/bold cyan]")
        try:
            agent = GeminiRemediationAgent()
            # Read the original file securely to send it to Gemini
            raw_content = read_file_securely(file_path)
            
            with console.status("[bold magenta]Gemini is analyzing vulnerabilities and rewriting the code...[/bold magenta]", spinner="bouncingBar"):
                ai_response = agent.generate_fix(raw_content, file_type, findings)
            
            if ai_response:
                # Use Rich Markdown to render the AI output beautifully
                console.print(Panel(Markdown(ai_response), title="[bold yellow]✨ AI Remediation & Fixed Code ✨[/bold yellow]", border_style="cyan"))
            else:
                console.print("[bold red][ERROR][/bold red] Gemini failed to generate a response.")
                
        except ValueError as ve:
            console.print(f"\n[bold red][SECURITY ERROR][/bold red] {ve}")
            console.print("[dim]Hint: Run 'export GEMINI_API_KEY=\"your_key\"' (Linux/Mac) or '$env:GEMINI_API_KEY=\"your_key\"' (PowerShell)[/dim]")
        except Exception as e:
            console.print(f"\n[bold red][ERROR][/bold red] AI Module encountered an issue: {e}")
    else:
        console.print("\n[dim]Run with --ai for automated contextual analysis and code fixing.[/dim]")

if __name__ == "__main__":
    app()