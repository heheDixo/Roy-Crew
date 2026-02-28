# modes/chat.py
from core.llm import LLMClient
from core.tools import ToolExecutor
from ui import terminal as ui
from core.rag import RAGPipeline


def clean_nmap_output(raw: str) -> str:
    clean_lines = []
    for line in raw.split('\n'):
        if any(x in line for x in [
            'open', 'closed', 'filtered',
            'Host is', 'PORT', 'SERVICE',
            'Nmap scan report', 'latency',
            'Not shown', 'Nmap done'
        ]) and 'FINGERPRINT' not in line and 'SF:' not in line:
            clean_lines.append(line)
    return '\n'.join(clean_lines)


def run_chat_mode():
    llm = LLMClient()
    executor = ToolExecutor()
    rag = RAGPipeline()

    ui.console.print(f"\n[dim]Available tools: {', '.join(executor.available_tools())}[/dim]")
    ui.console.print("[dim]Type 'quit' to exit, 'clear' to reset conversation[/dim]\n")

    while True:
        user_input = ui.get_input()

        if not user_input.strip():
            continue
        if user_input.lower() == "quit":
            break
        if user_input.lower() == "clear":
            llm.clear_history()
            ui.console.print("[dim]Conversation cleared.[/dim]")
            continue

        context = rag.retrieve(user_input)
        parsed = llm.chat(user_input, rag_context=context)

        if parsed["type"] == "tool_call":
            tool = parsed.get("tool", "")
            target = parsed.get("target", "")
            flags = parsed.get("flags", "")

            ui.print_tool_start(tool, target, flags)
            result = executor.run(tool, target, flags)

            # Clean for display
            display_output = result["output"]
            if tool == "nmap" and display_output:
                display_output = clean_nmap_output(display_output)

            ui.print_tool_result(
                tool,
                display_output or result["error"],
                result["success"]
            )

            if result["success"] and result["output"]:
                # Clean for analysis
                output = result["output"]
                if tool == "nmap":
                    output = clean_nmap_output(output)
                output = output[:1500]

                analysis_context = rag.retrieve(output)
                analysis = llm.inject_tool_result(tool, output, analysis_context)
                ui.print_analysis(analysis.get("content", "No analysis returned."))

            elif not result["success"]:
                ui.print_error(result["error"])

        else:
            ui.print_response(parsed["content"])