# modes/chat.py
from core.llm import LLMClient
from core.tools import ToolExecutor
from ui import terminal as ui
from core.rag import RAGPipeline

def run_chat_mode():
    llm = LLMClient()
    executor = ToolExecutor()
    rag = RAGPipeline()  # Initialize RAG

    while True:
        user_input = ui.get_input()
        if not user_input.strip():
            continue
        if user_input.lower() == "quit":
            break
        if user_input.lower() == "clear":
            llm.clear_history()
            continue

        # Retrieve context BEFORE sending to LLM
        context = rag.retrieve(user_input)
        parsed = llm.chat(user_input, rag_context=context)

        if parsed["type"] == "tool_call":
            tool = parsed.get("tool", "")
            target = parsed.get("target", "")
            flags = parsed.get("flags", "")

            ui.print_tool_start(tool, target, flags)
            result = executor.run(tool, target, flags)
            ui.print_tool_result(tool, result["output"] or result["error"], result["success"])

            if result["success"] and result["output"]:
                # Retrieve context for analysis too
                analysis_context = rag.retrieve(result["output"][:500])
                analysis = llm.inject_tool_result(tool, result["output"], analysis_context)
                ui.print_analysis(analysis.get("content", "No analysis returned."))
            elif not result["success"]:
                ui.print_error(result["error"])
        else:
            ui.print_response(parsed["content"])