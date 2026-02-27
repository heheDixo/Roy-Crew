# core/llm.py
import json
import re
from openai import OpenAI
from config.settings import MODEL, SYSTEM_PROMPT, OLLAMA_BASE_URL


class LLMClient:
    def __init__(self):
        self.client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="lm-studio")
        self.model = MODEL
        self.system_prompt = SYSTEM_PROMPT
        self.history = []

    def chat(self, user_input: str, rag_context: str = "") -> dict:
        self.history.append({"role": "user", "content": user_input})

        messages = [{"role": "system", "content": self.system_prompt}]

        if rag_context:
            messages.append({
                "role": "system",
                "content": f"RELEVANT KNOWLEDGE BASE CONTEXT:\n{rag_context}"
            })

        messages += self.history

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages
        )

        reply = response.choices[0].message.content.strip()
        self.history.append({"role": "assistant", "content": reply})
        return self._parse_reply(reply)

    def inject_tool_result(self, tool: str, result: str, rag_context: str = "") -> dict:
        summary_prompt = f"Tool '{tool}' returned the following output. Analyze it from a security perspective:\n\n{result}"
        return self.chat(summary_prompt, rag_context=rag_context)

    def _parse_reply(self, reply: str) -> dict:
        try:
            data = json.loads(reply)
            if "tool" in data:
                return {"type": "tool_call", **data}
        except json.JSONDecodeError:
            pass

        match = re.search(r'\{[^{}]+\}', reply, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if "tool" in data:
                    return {"type": "tool_call", **data}
            except json.JSONDecodeError:
                pass

        return {"type": "text", "content": reply}

    def clear_history(self):
        self.history = []