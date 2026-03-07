# core/agent.py
import json
from dataclasses import dataclass, field
from typing import Optional
from core.tools import ToolExecutor
from core.llm import LLMClient
from core.rag import RAGPipeline


@dataclass
class Finding:
    tool: str
    finding: str
    severity: str  # critical, high, medium, low, info
    details: str


@dataclass
class AgentState:
    target: str
    phase: str = "recon"
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    tech_stack: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    completed_tasks: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    should_stop: bool = False
    stop_reason: str = ""


class PentestAgent:
    def __init__(self, target: str):
        self.target = target
        self.state = AgentState(target=target)
        self.executor = ToolExecutor()
        self.llm = LLMClient()
        self.rag = RAGPipeline()
        self.max_retries = 2

    def run(self) -> dict:
        """Main agent loop — runs full pentest autonomously."""
        print(f"\n[Agent] Starting autonomous pentest on {self.target}")
        print("[Agent] Phase: RECON\n")

        # PTT execution
        self._phase_recon()
        if not self.state.should_stop:
            self._phase_scanning()
        if not self.state.should_stop:
            self._phase_enumeration()

        return self._generate_report()

    def _run_tool_with_retry(self, tool: str, target: str, flags: str = None, **kwargs) -> dict:
        """Run tool with retry logic."""
        for attempt in range(self.max_retries):
            result = self.executor.run(tool, target, flags, **kwargs)
            if result["success"]:
                return result
            print(f"[Agent] {tool} failed (attempt {attempt + 1}/{self.max_retries}): {result['error']}")
        return result

    def _analyze_with_llm(self, tool: str, output: str) -> dict:
        """Send tool output to LLM for analysis and state extraction."""
        context = self.rag.retrieve(output[:500])

        prompt = f"""Analyze this {tool} output and extract findings as JSON.

Target: {self.target}
Current state: {json.dumps({
    'open_ports': self.state.open_ports,
    'services': self.state.services,
    'tech_stack': self.state.tech_stack
})}

Tool output:
{output[:1500]}

Respond ONLY with JSON in this exact format:
{{
    "open_ports": [80, 443],
    "services": {{"80": "http", "443": "https"}},
    "tech_stack": ["PHP 5.6", "Nginx 1.19"],
    "directories": ["/admin", "/uploads"],
    "findings": [
        {{"finding": "PHP 5.6 end of life", "severity": "high", "details": "upgrade required"}}
    ],
    "next_action": "run_httpx",
    "reasoning": "why this next action"
}}"""

        response = self.llm.chat(prompt, rag_context=context)
        try:
            content = response.get("content", "{}")
            # Extract JSON from response
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            print(f"[Agent] LLM analysis failed: {e}")
        return {}

    def _update_state(self, analysis: dict):
        """Update agent state from LLM analysis."""
        if analysis.get("open_ports"):
            self.state.open_ports.extend(analysis["open_ports"])
            self.state.open_ports = list(set(self.state.open_ports))

        if analysis.get("services"):
            self.state.services.update(analysis["services"])

        if analysis.get("tech_stack"):
            self.state.tech_stack.extend(analysis["tech_stack"])
            self.state.tech_stack = list(set(self.state.tech_stack))

        if analysis.get("directories"):
            self.state.directories.extend(analysis["directories"])

        if analysis.get("findings"):
            for f in analysis["findings"]:
                self.state.findings.append(Finding(
                    tool="agent",
                    finding=f.get("finding", ""),
                    severity=f.get("severity", "info"),
                    details=f.get("details", "")
                ))

    def _phase_recon(self):
        """Phase 1 — Recon: identify open ports and services."""
        print("[Agent] Running nmap recon...")
        self.state.phase = "recon"

        result = self._run_tool_with_retry(
            "nmap", self.target,
            flags="-sT -sV --top-ports 100 -T4"
        )
        self.state.completed_tasks.append("nmap_recon")

        if result["success"]:
            analysis = self._analyze_with_llm("nmap", result["output"])
            self._update_state(analysis)
            print(f"[Agent] Found ports: {self.state.open_ports}")
            print(f"[Agent] Tech stack: {self.state.tech_stack}")
        else:
            print(f"[Agent] Nmap failed: {result['error']}")
            self.state.should_stop = True
            self.state.stop_reason = "Initial recon failed"

    def _phase_scanning(self):
        """Phase 2 — Scanning: probe web services."""
        print("\n[Agent] Phase: SCANNING")
        self.state.phase = "scanning"

        # Check if web ports are open
        web_ports = [p for p in self.state.open_ports if p in [80, 443, 8080, 8443, 8000]]

        if not web_ports:
            print("[Agent] No web ports found, skipping web scanning")
            return

        # Build target URL
        web_target = self.target
        if not web_target.startswith("http"):
            port = 443 if 443 in web_ports else 80
            protocol = "https" if port == 443 else "http"
            web_target = f"{protocol}://{self.target}"

        print(f"[Agent] Running httpx on {web_target}...")
        result = self._run_tool_with_retry("httpx", web_target)
        self.state.completed_tasks.append("httpx_probe")

        if result["success"]:
            analysis = self._analyze_with_llm("httpx", result["output"])
            self._update_state(analysis)

    def _phase_enumeration(self):
        """Phase 3 — Enumeration: directory brute force."""
        print("\n[Agent] Phase: ENUMERATION")
        self.state.phase = "enumeration"

        web_target = self.target
        if not web_target.startswith("http"):
            web_target = f"http://{self.target}"

        print(f"[Agent] Running gobuster on {web_target}...")
        result = self._run_tool_with_retry(
            "gobuster", web_target,
            wordlist="knowledge/wordlists/common.txt"
        )
        self.state.completed_tasks.append("gobuster_enum")

        if result["success"]:
            analysis = self._analyze_with_llm("gobuster", result["output"])
            self._update_state(analysis)
            print(f"[Agent] Found directories: {self.state.directories}")

    def _generate_report(self) -> dict:
        """Generate final pentest report."""
        print("\n[Agent] Generating report...")

        report = {
            "target": self.target,
            "phases_completed": self.state.completed_tasks,
            "open_ports": self.state.open_ports,
            "services": self.state.services,
            "tech_stack": self.state.tech_stack,
            "directories": self.state.directories,
            "findings": [
                {
                    "finding": f.finding,
                    "severity": f.severity,
                    "details": f.details
                }
                for f in self.state.findings
            ],
            "stop_reason": self.state.stop_reason
        }

        return report