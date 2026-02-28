"""MCP (Model Context Protocol) server management for GHOSTCREW."""

import json
import os
from typing import List, Optional, Tuple
from colorama import Fore, Style
from config.constants import MCP_SESSION_TIMEOUT, MCP_CONFIG_FILE


class MCPManager:
    """Manages MCP server connections and configuration."""
    
    def __init__(self, MCPServerStdio=None, MCPServerSse=None):
        """
        Initialize the MCP manager.
        
        Args:
            MCPServerStdio: MCP server stdio class
            MCPServerSse: MCP server SSE class
        """
        self.MCPServerStdio = MCPServerStdio
        self.MCPServerSse = MCPServerSse
        self.server_instances = []
        self.connected_servers = []
    
    @staticmethod
    def get_available_tools(connected_servers: List) -> List[str]:
        """Get list of available/connected tool names."""
        return [server.name for server in connected_servers]
    
    def load_mcp_config(self) -> List[dict]:
        """Load MCP tool configurations from mcp.json."""
        available_tools = []
        try:
            with open(MCP_CONFIG_FILE, 'r', encoding='utf-8') as f:
                mcp_config = json.load(f)
                available_tools = mcp_config.get('servers', [])
        except FileNotFoundError:
            print(f"{Fore.YELLOW}mcp.json configuration file not found.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error loading MCP configuration file: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Proceeding without MCP tools.{Style.RESET_ALL}")
        return available_tools
    
    def display_tool_menu(self, available_tools: List[dict]) -> Optional[List[int]]:
        """Display MCP tool selection menu and get user choice."""
        if not available_tools:
            print(f"{Fore.YELLOW}No MCP tools currently configured.{Style.RESET_ALL}")
            configure_now = input(f"{Fore.YELLOW}Would you like to add tools? (yes/no, default: no): {Style.RESET_ALL}").strip().lower()
            if configure_now == 'yes':
                print(f"\n{Fore.CYAN}Launching tool configuration...{Style.RESET_ALL}")
                os.system("python tools/configure_mcp.py")
                print(f"\n{Fore.GREEN}Tool configuration completed.{Style.RESET_ALL}")
                # Reload configuration and continue
                return "reload_and_continue"
            else:
                print(f"{Fore.YELLOW}Proceeding without MCP tools.{Style.RESET_ALL}")
                return []
        
        print(f"\n{Fore.CYAN}Available MCP tools:{Style.RESET_ALL}")
        for i, server in enumerate(available_tools):
            print(f"{i+1}. {server['name']}")
        print(f"{len(available_tools)+1}. Configure new tools")
        print(f"{len(available_tools)+2}. Connect to all tools")
        print(f"{len(available_tools)+3}. Skip tool connection")
        print(f"{len(available_tools)+4}. Clear all MCP tools")
        
        try:
            tool_choice = input(f"\n{Fore.YELLOW}Select option: {Style.RESET_ALL}").strip()
            
            if not tool_choice:  # Default to all tools
                return list(range(len(available_tools)))
            elif tool_choice == str(len(available_tools)+1):  # Configure new tools
                print(f"\n{Fore.CYAN}Launching tool configuration...{Style.RESET_ALL}")
                os.system("python tools/configure_mcp.py")
                print(f"\n{Fore.GREEN}Tool configuration completed.{Style.RESET_ALL}")
                # Reload configuration and continue
                return "reload_and_continue"
            elif tool_choice == str(len(available_tools)+2):  # Connect to all tools
                return list(range(len(available_tools)))
            elif tool_choice == str(len(available_tools)+3):  # Skip tool connection
                return []
            elif tool_choice == str(len(available_tools)+4):  # Clear all MCP tools
                if self.clear_mcp_tools():
                    return "reload_and_continue"
                return []
            else:  # Parse comma-separated list
                selected_indices = []
                for part in tool_choice.split(","):
                    idx = int(part.strip()) - 1
                    if 0 <= idx < len(available_tools):
                        selected_indices.append(idx)
                return selected_indices
        except ValueError:
            print(f"{Fore.RED}Invalid selection. Defaulting to all tools.{Style.RESET_ALL}")
            return list(range(len(available_tools)))
    
    def clear_mcp_tools(self) -> bool:
        """Clear all MCP tools from configuration."""
        confirm = input(f"{Fore.YELLOW}Are you sure you want to clear all MCP tools? This will empty mcp.json (yes/no): {Style.RESET_ALL}").strip().lower()
        if confirm == "yes":
            try:
                # Create empty mcp.json file
                with open(MCP_CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump({"servers": []}, f, indent=2)
                print(f"{Fore.GREEN}Successfully cleared all MCP tools. mcp.json has been reset.{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}Error clearing MCP tools: {e}{Style.RESET_ALL}")
        return False
    
    def initialize_servers(self, available_tools: List[dict], selected_indices: List[int]) -> None:
        """Initialize selected MCP servers."""
        # Use the MCP classes passed during initialization
        if not self.MCPServerStdio or not self.MCPServerSse:
            raise ValueError("MCP server classes not provided during initialization")
        
        print(f"{Fore.GREEN}Initializing selected MCP servers...{Style.RESET_ALL}")
        for idx in selected_indices:
            if idx < len(available_tools):
                server = available_tools[idx]
                print(f"{Fore.CYAN}Initializing {server['name']}...{Style.RESET_ALL}")
                try:
                    if 'params' in server:
                        mcp_server = self.MCPServerStdio(
                            name=server['name'],
                            params=server['params'],
                            cache_tools_list=server.get('cache_tools_list', True),
                            client_session_timeout_seconds=MCP_SESSION_TIMEOUT
                        )
                    elif 'url' in server:
                        mcp_server = self.MCPServerSse(
                            params={"url": server["url"]},
                            cache_tools_list=server.get('cache_tools_list', True),
                            name=server['name'],
                            client_session_timeout_seconds=MCP_SESSION_TIMEOUT
                        )
                    else:
                        print(f"{Fore.RED}Unknown MCP server configuration: {server}{Style.RESET_ALL}")
                        continue
                    self.server_instances.append(mcp_server)
                except Exception as e:
                    print(f"{Fore.RED}Error initializing {server['name']}: {e}{Style.RESET_ALL}")
    
    async def connect_servers(self) -> List:
        """Connect to initialized MCP servers."""
        if not self.server_instances:
            return []
        
        print(f"{Fore.YELLOW}Connecting to MCP servers...{Style.RESET_ALL}")
        for mcp_server in self.server_instances:
            try:
                await mcp_server.connect()
                print(f"{Fore.GREEN}Successfully connected to MCP server: {mcp_server.name}{Style.RESET_ALL}")
                self.connected_servers.append(mcp_server)
            except Exception as e:
                print(f"{Fore.RED}Failed to connect to MCP server {mcp_server.name}: {e}{Style.RESET_ALL}")
        
        if self.connected_servers:
            print(f"{Fore.GREEN}MCP server connection successful! Can use tools provided by {len(self.connected_servers)} servers.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}No MCP servers successfully connected. Proceeding without tools.{Style.RESET_ALL}")
        
        return self.connected_servers
    
    async def setup_mcp_tools(self, use_mcp: bool = False) -> Tuple[List, List]:
        """
        Main method to setup MCP tools.
        
        Args:
            use_mcp: Whether to use MCP tools
            
        Returns:
            Tuple of (server_instances, connected_servers)
        """
        if not use_mcp:
            print(f"{Fore.YELLOW}Proceeding without MCP tools.{Style.RESET_ALL}")
            return [], []
        
        while True:  # Loop to handle configuration and reload
            # Load available tools
            available_tools = self.load_mcp_config()
            
            # Get user selection
            selected_indices = self.display_tool_menu(available_tools)
            
            # Handle special cases
            if selected_indices is None:
                # Restart needed (e.g., after clearing tools)
                return self.server_instances, []
            elif selected_indices == "reload_and_continue":
                # Tools were configured, reload and show menu again
                continue
            else:
                # Normal selection, proceed with initialization
                break
        
        # Initialize servers
        if selected_indices:
            self.initialize_servers(available_tools, selected_indices)
        
        # Connect to servers
        connected = await self.connect_servers()
        
        return self.server_instances, connected
    
    async def cleanup_servers(self) -> None:
        """Clean up MCP server resources."""
        if not self.server_instances:
            return
        
        print(f"{Fore.YELLOW}Cleaning up MCP server resources...{Style.RESET_ALL}")
        
        for mcp_server in self.server_instances:
            print(f"{Fore.YELLOW}Attempting to clean up server: {mcp_server.name}...{Style.RESET_ALL}", flush=True)
            try:
                await mcp_server.cleanup()
                print(f"{Fore.GREEN}Cleanup completed for {mcp_server.name}.{Style.RESET_ALL}", flush=True)
            except Exception:
                print(f"{Fore.RED}Failed to cleanup {mcp_server.name}.{Style.RESET_ALL}", flush=True)
        
        print(f"{Fore.YELLOW}MCP server resource cleanup complete.{Style.RESET_ALL}") 