# core/tools.py
import json
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class ToolExecutor:
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = BASE_DIR / "config" / "tools_config.json"
        with open(config_path) as f:
            self.tools = json.load(f)

    def available_tools(self) -> list:
        return list(self.tools.keys())

    def run(self, tool_name: str, target: str, flags: str = None, **kwargs) -> dict:
    # Try MCP first
        mcp_result = self._try_mcp(tool_name, target, flags, **kwargs)
        if mcp_result is not None:
            return mcp_result
        return self._run_subprocess(tool_name, target, flags, **kwargs)

    def _try_mcp(self, tool_name: str, target: str, flags: str, **kwargs) -> dict | None:
        try:
            from core.mcp_client import MCPClient
            mcp = MCPClient()

            tool_to_server = {
                "nmap": "nmap_scanner",
                "ffuf": "ffuf_fuzzer"
            }

            server_name = tool_to_server.get(tool_name)
            if not server_name or server_name not in mcp.available_servers():
             return None

            if tool_name == "nmap":
                return mcp.run_tool(server_name, "do-nmap", {
                    "target": target,
                    "nmap_args": flags or "-sT --top-ports 100"
                })

            if tool_name == "ffuf":
                wordlist = kwargs.get("wordlist", "knowledge/wordlists/common.txt")
                return mcp.run_tool(server_name, "do-ffuf", {
                    "url": f"{target}/FUZZ",
                    "ffuf_args": f"-w {wordlist} -c -mc 200,301,302,403"
                })

            return None

        except Exception as e:
            print(f"[MCP] Failed for {tool_name}: {e}, falling back to subprocess")
            return None
    
    def _run_subprocess(self, tool_name: str, target: str, flags: str = None, **kwargs) -> dict:
        if tool_name not in self.tools:
            return {"success": False, "output": "", "error": f"Unknown tool: {tool_name}"}

        tool_config = self.tools[tool_name]
        command = tool_config["command"]

        args_str = tool_config["args_template"].format(
            target=target,
            flags=flags or tool_config.get("default_flags", ""),
            wordlist=kwargs.get("wordlist") or tool_config.get("default_wordlist", "")
        )

        cmd = [command] + [a for a in args_str.split() if a]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if tool_name == "nmap" and (
                "0 hosts up" in result.stdout or
                "Host seems down" in result.stdout
            ):
                return {
                    "success": False,
                    "output": result.stdout,
                    "error": "Host appears down or blocking probes. Try adding -Pn flag."
                }

            if result.returncode == 0:
                return {"success": True, "output": result.stdout, "error": ""}
            else:
                return {"success": False, "output": result.stdout, "error": result.stderr}

        except FileNotFoundError:
            return {"success": False, "output": "", "error": f"'{command}' not found. Is it installed and in PATH?"}
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": f"Tool '{tool_name}' timed out after 300s"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}