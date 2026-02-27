# main.py
import sys
from ui import terminal as ui
from modes.chat import run_chat_mode


def select_mode() -> str:
    ui.console.print("\n[bold]Select Mode:[/bold]")
    ui.console.print("  [cyan]1[/cyan] → Chat Mode")
    ui.console.print("  [dim]2 → Workflow Mode (coming soon)[/dim]")
    ui.console.print("  [dim]3 → Agent Mode (coming soon)[/dim]\n")

    choice = ui.console.input("[bold green]Select> [/bold green]").strip()
    return choice


def main():
    ui.print_banner()

    mode = select_mode()

    if mode == "1" or mode == "":
        run_chat_mode()
    else:
        ui.console.print("[dim]Mode not available yet. Starting Chat Mode.[/dim]")
        run_chat_mode()

    ui.console.print("\n[bold red]Session ended.[/bold red]")


if __name__ == "__main__":
    main()