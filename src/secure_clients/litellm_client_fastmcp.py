"""LiteLLM integration with FastMCP OAuth authentication."""

import asyncio
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from fastmcp import Client
from fastmcp.client.auth import OAuth
import litellm

from config import Config

# Load environment variables
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class FastMCPLiteLLMClient:
    """LiteLLM client with FastMCP OAuth integration."""

    def __init__(self, mcp_url: str = None):
        """Initialize the LiteLLM MCP client with FastMCP OAuth."""
        self.mcp_url = mcp_url or Config.get_mcp_oauth_url()
        self.client = None
        self.tools = []
        self.exit_stack = AsyncExitStack()

        # Configure LiteLLM for custom OpenAI endpoints
        if Config.LLM_PROVIDER == "openai":
            if Config.OPENAI_BASE_URL:
                # LiteLLM expects OPENAI_API_BASE, but we standardize on OPENAI_BASE_URL
                os.environ["OPENAI_API_BASE"] = Config.OPENAI_BASE_URL
                print(
                    f"🔧 LiteLLM configured for custom OpenAI endpoint: {Config.OPENAI_BASE_URL}"
                )
            if Config.OPENAI_API_KEY:
                os.environ["OPENAI_API_KEY"] = Config.OPENAI_API_KEY

        # Configure FastMCP OAuth client - let server handle Azure scopes
        self.oauth = OAuth(
            mcp_url=self.mcp_url,
            client_name="LiteLLM FastMCP Client",
        )

    async def connect(self):
        """Connect to MCP server using FastMCP OAuth."""
        try:
            print("🔗 Connecting to MCP server with FastMCP OAuth...")
            self.client = await self.exit_stack.enter_async_context(
                Client(self.mcp_url, auth=self.oauth)
            )
            print("✅ FastMCP OAuth connection successful")

            # Load available tools
            await self.load_tools()
            return True
        except Exception as e:
            print(f"❌ Failed to connect with FastMCP OAuth: {e}")
            return False

    async def disconnect(self):
        """Disconnect from MCP server."""
        try:
            await self.exit_stack.aclose()
            print("🔗 Disconnected from MCP server")
        except Exception as e:
            print(f"⚠️ Error during disconnect: {e}")

    async def load_tools(self):
        """Load available tools from the MCP server."""
        try:
            result = await self.client.list_tools()
            self.tools = []

            # Convert MCP tools to LiteLLM function format
            for tool in result.tools:
                litellm_tool = {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": tool.inputSchema
                        or {"type": "object", "properties": {}},
                    },
                }
                self.tools.append(litellm_tool)

            print(f"🔧 Loaded {len(self.tools)} tools from MCP server")
            for tool in result.tools:
                print(f"   - {tool.name}: {tool.description}")
        except Exception as e:
            print(f"❌ Failed to load tools: {e}")
            self.tools = []

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the MCP server."""
        try:
            result = await self.client.call_tool(tool_name, arguments)
            if result.isError:
                raise Exception(f"Tool error: {result.content}")
            return result.content
        except Exception as e:
            print(f"❌ Tool call failed: {e}")
            raise

    def get_tools_for_litellm(self) -> List[Dict[str, Any]]:
        """Get tools formatted for LiteLLM."""
        return self.tools

    async def run_conversation(self, messages: List[Dict[str, str]]) -> str:
        """Run a conversation using LiteLLM with MCP tools."""
        try:
            if not self.tools:
                await self.load_tools()

            # Use LiteLLM completion with tools
            response = await litellm.acompletion(
                model=Config.OPENAI_MODEL,
                messages=messages,
                tools=self.tools,
                tool_choice="auto",
            )

            message = response.choices[0].message

            # Handle tool calls
            if message.tool_calls:
                print("🔧 LLM requested tool calls:")

                # Add assistant message with tool calls
                messages.append(
                    {
                        "role": "assistant",
                        "content": message.content,
                        "tool_calls": message.tool_calls,
                    }
                )

                # Execute each tool call
                for tool_call in message.tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)

                    print(f"   📞 Calling {tool_name} with {tool_args}")

                    try:
                        tool_result = await self.call_tool(tool_name, tool_args)

                        # Add tool result to messages
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "name": tool_name,
                                "content": str(tool_result),
                            }
                        )

                        print(f"   ✅ Tool result: {str(tool_result)[:100]}...")

                    except Exception as e:
                        print(f"   ❌ Tool execution failed: {e}")
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "name": tool_name,
                                "content": f"Error: {str(e)}",
                            }
                        )

                # Get final response with tool results
                final_response = await litellm.acompletion(
                    model=Config.OPENAI_MODEL, messages=messages
                )

                return final_response.choices[0].message.content

            else:
                return message.content

        except Exception as e:
            print(f"❌ Conversation failed: {e}")
            raise

    async def run_demo(self):
        """Run a comprehensive demo of LiteLLM with FastMCP."""
        print("🚀 Starting FastMCP LiteLLM Demo")
        print("=" * 50)

        try:
            # Connect to MCP server
            if not await self.connect():
                return

            # Demo conversation
            messages = [
                {
                    "role": "system",
                    "content": "You are a helpful customer service assistant. Use the available tools to help customers.",
                },
                {
                    "role": "user",
                    "content": "Can you get information for customer ID 12345 and calculate their account value?",
                },
            ]

            print("💬 Running demo conversation...")
            result = await self.run_conversation(messages)

            print("🎉 Demo Results:")
            print("-" * 30)
            print(result)

        except Exception as e:
            print(f"❌ Demo failed: {e}")
            raise
        finally:
            await self.disconnect()


async def main():
    """Main function to run the FastMCP LiteLLM demo."""
    print("🔍 Checking FastMCP server availability...")
    endpoints = Config.get_fastmcp_oauth_endpoints()
    print(f"   MCP URL: {endpoints['mcp_url']}")

    # Initialize and run client
    client = FastMCPLiteLLMClient()
    await client.run_demo()


if __name__ == "__main__":
    asyncio.run(main())
