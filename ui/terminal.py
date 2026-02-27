# ui/terminal.py
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

console = Console()


def print_banner():
    banner = Text()
    banner.append("  ██████╗  ██████╗ ██╗   ██╗ ██████╗██████╗ ███████╗██╗    ██╗\n", style="bold red")
    banner.append("  ██╔══██╗██╔═══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██║    ██║\n", style="bold red")
    banner.append("  ██████╔╝██║   ██║ ╚████╔╝ ██║     ██████╔╝█████╗  ██║ █╗ ██║\n", style="bold red")
    banner.append("  ██╔══██╗██║   ██║  ╚██╔╝  ██║     ██╔══██╗██╔══╝  ██║███╗██║\n", style="bold red")
    banner.append("  ██║  ██║╚██████╔╝   ██║   ╚██████╗██║  ██║███████╗╚███╔███╔╝\n", style="bold red")
    banner.append("  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ \n", style="bold red")
    console.print(Panel(banner, subtitle="[dim]AI Red Team Assistant[/dim]", border_style="red"))


def print_response(content: str):
    console.print(Panel(content, title="[bold cyan]ROYCrew[/bold cyan]", border_style="cyan"))


def print_tool_start(tool: str, target: str, flags: str):
    console.print(Panel(
        f"[yellow]Tool:[/yellow] {tool}\n[yellow]Target:[/yellow] {target}\n[yellow]Flags:[/yellow] {flags}",
        title="[bold yellow]⚡ Executing Tool[/bold yellow]",
        border_style="yellow"
    ))


def print_tool_result(tool: str, output: str, success: bool):
    style = "green" if success else "red"
    status = "✓ Success" if success else "✗ Failed"
    console.print(Panel(
        output[:3000] + ("...[truncated]" if len(output) > 3000 else ""),
        title=f"[bold {style}]{status} — {tool}[/bold {style}]",
        border_style=style
    ))


def print_analysis(content: str):
    console.print(Panel(content, title="[bold magenta]🔍 Analysis[/bold magenta]", border_style="magenta"))


def print_error(message: str):
    console.print(f"[bold red]ERROR:[/bold red] {message}")


def get_input() -> str:
    return console.input("\n[bold green]roycrew> [/bold green]")