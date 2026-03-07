# main.py
from ui import terminal as ui
from modes.chat import run_chat_mode
from modes.agent import run_agent_mode


def select_mode():
    ui.console.print("\nSelect Mode:")
    ui.console.print("  1 → Chat Mode")
    ui.console.print("  2 → Agent Mode (Autonomous Pentest)")
    ui.console.print("  3 → Exit\n")
    return input("Select> ").strip()


def main():
    ui.print_banner()

    while True:
        choice = select_mode()

        if choice == "1":
            run_chat_mode()
        elif choice == "2":
            run_agent_mode()
        elif choice == "3":
            ui.console.print("[dim]Goodbye.[/dim]")
            break
        else:
            ui.console.print("[dim]Invalid choice.[/dim]")

        # After mode exits, show menu again
        ui.console.print("\n[dim]Returning to main menu...[/dim]")


if __name__ == "__main__":
    main()