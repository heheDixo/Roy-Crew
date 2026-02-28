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
        
        self.config_path = config_path
        self.servers = {}
        
        if Path(config_path).exists():
            with open(config_path) as f:
                self.servers = json.load(f)
        else:
            print("[MCP] No mcp.json found. Create one to add MCP tools.")

    def available_servers(self) -> list:
        return list(self.servers.keys())

    async def list_tools(self, server_name: str) -> list:
        """List all tools available on a MCP server."""
        if server_name not in self.servers:
            return []

        server_config = self.servers[server_name]
        server_params = StdioServerParameters(
            command=server_config["command"],
            args=server_config.get("args", []),
            env=server_config.get("env", {})
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return [t.name for t in tools.tools]

    async def call_tool(self, server_name: str, tool_name: str, args: dict) -> dict:
        """Call a tool on a MCP server."""
        if server_name not in self.servers:
            return {"success": False, "output": "", "error": f"Unknown server: {server_name}"}

        server_config = self.servers[server_name]
        server_params = StdioServerParameters(
            command=server_config["command"],
            args=server_config.get("args", []),
            env=server_config.get("env", {})
        )

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, args)
                    
                    # Extract text content from result
                    output = ""
                    for block in result.content:
                        if hasattr(block, 'text'):
                            output += block.text

                    return {"success": True, "output": output, "error": ""}

        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def run_tool(self, server_name: str, tool_name: str, args: dict) -> dict:
        """Synchronous wrapper for async call_tool."""
        return asyncio.run(self.call_tool(server_name, tool_name, args))