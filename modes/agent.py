# modes/agent.py
import json
from core.agent import PentestAgent
from ui import terminal as ui


def run_agent_mode():

    
    ui.console.print("\n[bold red]⚡ AGENT MODE — Autonomous Pentest[/bold red]\n")
    ui.console.print("[dim]Agent will autonomously run recon → scanning → enumeration[/dim]\n")

    target = input("Enter target (IP or domain): ").strip()
    
    if not target or target.lower() == "quit":
        ui.console.print("[red]No target provided. OR Cancelled[/red]")
        return

    ui.console.print(f"\n[yellow]Starting autonomous pentest on {target}...[/yellow]\n")

    agent = PentestAgent(target)
    report = agent.run()

    # Display report
    ui.console.print("\n[bold green]═══════════════ PENTEST REPORT ═══════════════[/bold green]")
    ui.console.print(f"[bold]Target:[/bold] {report['target']}")
    ui.console.print(f"[bold]Phases completed:[/bold] {', '.join(report['phases_completed'])}")
    ui.console.print(f"[bold]Open ports:[/bold] {report['open_ports']}")
    ui.console.print(f"[bold]Tech stack:[/bold] {report['tech_stack']}")
    ui.console.print(f"[bold]Directories:[/bold] {report['directories']}")

    if report["findings"]:
        ui.console.print("\n[bold red]FINDINGS:[/bold red]")
        for f in report["findings"]:
            severity_color = {
                "critical": "red", "high": "red",
                "medium": "yellow", "low": "blue", "info": "dim"
            }.get(f["severity"], "white")
            ui.console.print(f"[{severity_color}][{f['severity'].upper()}][/{severity_color}] {f['finding']}")
            ui.console.print(f"  [dim]{f['details']}[/dim]")

    ui.console.print("\n[bold green]═══════════════════════════════════════════[/bold green]")

    # Save report
    report_path = f"reports/{report['target'].replace('/', '_').replace(':', '_')}_report.json"
    import os
    os.makedirs("reports", exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    ui.console.print(f"\n[dim]Report saved to {report_path}[/dim]")