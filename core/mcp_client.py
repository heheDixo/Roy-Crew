# core/mcp_client.py
import asyncio
import json
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE_DIR = Path(__file__).resolve().parent.parent


class MCPClient:
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = BASE_DIR / "config" / "mcp.json"

        self.servers = {}

        if Path(config_path).exists():
            with open(config_path) as f:
                data = json.load(f)
                # Convert list structure to dict keyed by name
                for server in data.get("servers", []):
                    name = server["name"].lower().replace(" ", "_")
                    self.servers[name] = server["params"]
        else:
            print("[MCP] No mcp.json found.")

    def available_servers(self) -> list:
        return list(self.servers.keys())

    def _get_server_params(self, server_name: str) -> StdioServerParameters | None:
        if server_name not in self.servers:
            return None
        config = self.servers[server_name]
        return StdioServerParameters(
            command=config["command"],
            args=config.get("args", []),
            env=config.get("env", {})
        )

    async def list_tools(self, server_name: str) -> list:
        params = self._get_server_params(server_name)
        if not params:
            return []
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return [t.name for t in tools.tools]

    async def call_tool(self, server_name: str, tool_name: str, args: dict) -> dict:
        params = self._get_server_params(server_name)
        if not params:
            return {"success": False, "output": "", "error": f"Unknown server: {server_name}"}
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                # Add 60 second timeout
                    result = await asyncio.wait_for(
                        session.call_tool(tool_name, args),
                        timeout=60.0
                    )
                    output = ""
                    for block in result.content:
                        if hasattr(block, 'text'):
                            output += block.text
                    return {"success": True, "output": output, "error": ""}
        except asyncio.TimeoutError:
            return {"success": False, "output": "", "error": f"MCP tool timed out after 60s"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}
    def run_tool(self, server_name: str, tool_name: str, args: dict) -> dict:
        return asyncio.run(self.call_tool(server_name, tool_name, args))