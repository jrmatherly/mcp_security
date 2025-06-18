"""
Secure LangChain integration with OAuth-protected MCP server.
Demonstrates how to connect LangChain agents to a secure MCP backend.
"""

import asyncio
import json
import time
import os
from typing import Dict, List, Optional
import httpx
from contextlib import AsyncExitStack
from dotenv import load_dotenv

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
import jwt

# Load environment variables from .env file
# Find .env file in project root (go up from src/secure_clients/)
from pathlib import Path

# Import config for model settings
import sys
sys.path.append(str(Path(__file__).parent.parent))
from config import Config
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)

class SecureLangChainMCPClient:
    """LangChain client with comprehensive MCP security integration."""
    
    def __init__(self, openai_api_key: str, oauth_config: dict):
        self.openai_api_key = openai_api_key
        self.oauth_config = oauth_config
        self.access_token = None
        self.token_expires_at = 0
        self.sessions = []
        self.exit_stack = AsyncExitStack()
        self.available_tools = []
        self.tool_to_session = {}
        self.agent = None

        # Configure secure HTTP client with TLS verification
        ca_cert_path = oauth_config.get('ca_cert_path', None)
        
        # Check for SSL environment variables (used by mkcert script)
        ssl_cert_file = os.environ.get('SSL_CERT_FILE')
        if ssl_cert_file and os.path.exists(ssl_cert_file):
            ca_cert_path = ssl_cert_file
            if os.environ.get('DEBUG_SSL'):
                print(f"🔐 Using SSL_CERT_FILE: {ssl_cert_file}")
        
        self.http_client = httpx.AsyncClient(
            verify=ca_cert_path if ca_cert_path else True,
            timeout=30.0
        )

    async def get_oauth_token(self) -> str:
        """Obtain OAuth access token using client credentials flow."""
        current_time = time.time()

        # Check if we have a valid token
        if self.access_token and current_time < self.token_expires_at - 60:
            return self.access_token

        # Request new token using the configured HTTP client
        response = await self.http_client.post(
            self.oauth_config['token_url'],
            data={
                'grant_type': 'client_credentials',
                'client_id': self.oauth_config['client_id'],
                'client_secret': self.oauth_config['client_secret'],
                'scope': self.oauth_config['scopes']
            }
        )

        if response.status_code != 200:
            raise Exception(f"OAuth token request failed: {response.text}")

        token_data = response.json()
        self.access_token = token_data['access_token']

        # Calculate token expiration
        expires_in = token_data.get('expires_in', 3600)
        self.token_expires_at = current_time + expires_in

        return self.access_token

    async def connect_to_secure_mcp_server(self):
        """Connect to OAuth-protected MCP server."""
        # Get fresh access token
        access_token = await self.get_oauth_token()

        # Create custom httpx client factory with our CA bundle
        def custom_httpx_client_factory(headers=None, timeout=None, auth=None):
            # Get the same CA cert path we use for the main client
            ca_cert_path = self.oauth_config.get('ca_cert_path', None)
            ssl_cert_file = os.environ.get('SSL_CERT_FILE')
            if ssl_cert_file and os.path.exists(ssl_cert_file):
                ca_cert_path = ssl_cert_file
                if os.environ.get('DEBUG_SSL'):
                    print(f"🔐 MCP client using SSL_CERT_FILE: {ssl_cert_file}")
            
            return httpx.AsyncClient(
                headers=headers,
                timeout=timeout if timeout else httpx.Timeout(30.0),
                auth=auth,
                verify=ca_cert_path if ca_cert_path else True,
                follow_redirects=True
            )

        # Create HTTP client with authentication headers and custom SSL verification
        http_transport = await self.exit_stack.enter_async_context(
            streamablehttp_client(
                url=self.oauth_config['mcp_server_url'],
                headers={"Authorization": f"Bearer {access_token}"},
                httpx_client_factory=custom_httpx_client_factory
            )
        )

        read, write, url_getter = http_transport
        session = await self.exit_stack.enter_async_context(
            ClientSession(read, write)
        )

        # Initialize with auth headers
        await session.initialize()

        self.sessions.append(session)

        # Discover available tools
        response = await session.list_tools()
        for tool in response.tools:
            self.tool_to_session[tool.name] = session

            # Convert to LangChain-compatible tool format
            langchain_tool = {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
                "session": session  # Store session reference for execution
            }
            self.available_tools.append(langchain_tool)

    def _get_required_scopes(self, tool_name: str) -> List[str]:
        """Map tool names to required OAuth scopes."""
        scope_mapping = {
            "get_customer_info": ["customer:read"],
            "create_support_ticket": ["ticket:create"],
            "calculate_account_value": ["account:calculate"],
            "get_recent_customers": ["customer:read"]
        }
        return scope_mapping.get(tool_name, [])

    async def _verify_token_scopes(self, required_scopes: List[str]) -> bool:
        """Verify the current token has required scopes."""
        if not self.access_token:
            return False

        try:
            # Decode token to check scopes (assuming JWT)
            # In production, verify signature with public key
            payload = jwt.decode(
                self.access_token,
                options={"verify_signature": False}
            )
            token_scopes = payload.get('scope', '').split()
            return all(scope in token_scopes for scope in required_scopes)
        except:
            return False

    async def call_mcp_tool(self, tool_name: str, tool_input: dict):
        """Call MCP tool with security validation."""
        # Verify we have required scopes for this tool
        required_scopes = self._get_required_scopes(tool_name)
        if not await self._verify_token_scopes(required_scopes):
            raise PermissionError(
                f"Insufficient permissions for {tool_name}"
            )
        
        # Get session for tool
        session = self.tool_to_session[tool_name]
        
        # Call the tool
        result = await session.call_tool(
            tool_name,
            arguments=tool_input
        )
        return result

    async def setup_langchain_agent(self):
        """Set up a LangChain agent with secure MCP tools."""
        
        # Initialize the language model
        llm = ChatOpenAI(
            model=Config.OPENAI_MODEL,
            temperature=0.1,
            api_key=self.openai_api_key
        )

        # Convert MCP tools to LangChain tools format
        from langchain.tools import BaseTool
        from pydantic import Field
        from typing import Any, Dict

        class SecureMCPTool(BaseTool):
            """Secure MCP tool wrapper for LangChain."""
            name: str
            description: str
            mcp_tool: Dict = Field(default_factory=dict, exclude=True)
            client: Any = Field(default=None, exclude=True)
            
            def __init__(self, mcp_tool: dict, client: 'SecureLangChainMCPClient', **kwargs):
                super().__init__(
                    name=mcp_tool["name"],
                    description=mcp_tool["description"],
                    **kwargs
                )
                self.mcp_tool = mcp_tool
                self.client = client

            async def _arun(self, **kwargs) -> str:
                """Execute the MCP tool securely."""
                try:
                    result = await self.client.call_mcp_tool(
                        self.mcp_tool["name"], 
                        kwargs
                    )
                    
                    # Extract content from MCP result
                    if hasattr(result, 'content') and result.content:
                        content = result.content[0].text if result.content else ""
                        return content
                    else:
                        return f"Tool {self.mcp_tool['name']} completed successfully"
                        
                except Exception as e:
                    return f"Error executing {self.mcp_tool['name']}: {str(e)}"

            def _run(self, **kwargs) -> str:
                """Synchronous run not supported."""
                raise NotImplementedError("Use async version")

        # Create LangChain tools from MCP tools
        langchain_tools = []
        for mcp_tool in self.available_tools:
            tool = SecureMCPTool(mcp_tool, self)
            langchain_tools.append(tool)

        # Create a ReAct agent with the secure tools
        self.agent = create_react_agent(llm, langchain_tools)
        
        return self.agent

    async def process_scenarios(self, scenarios: List[str]):
        """Process multiple scenarios with the LangChain agent."""
        if not self.agent:
            raise RuntimeError("Agent not initialized. Call setup_langchain_agent() first.")

        results = []
        
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n📞 Scenario {i}: {scenario}")
            try:
                response = await self.agent.ainvoke(
                    {"messages": [{"role": "user", "content": scenario}]}
                )

                # Extract the final AI response
                final_message = response["messages"][-1]
                if hasattr(final_message, "content"):
                    content = final_message.content
                else:
                    content = str(final_message)
                
                print(f"🤖 LangChain Agent Response: {content}")
                results.append({"scenario": scenario, "response": content, "status": "success"})

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    # Token expired, refresh and retry
                    self.access_token = None
                    print("🔄 Token expired, refreshing and retrying...")
                    return await self.process_scenarios([scenario])  # Retry this scenario
                elif e.response.status_code == 429:
                    # Handle rate limiting
                    retry_after = int(e.response.headers.get('Retry-After', 60))
                    print(f"⏳ Rate limited. Waiting {retry_after} seconds...")
                    await asyncio.sleep(retry_after)
                    return await self.process_scenarios([scenario])  # Retry this scenario
                else:
                    print(f"❌ HTTP Error: {e}")
                    results.append({"scenario": scenario, "error": str(e), "status": "error"})
            except Exception as e:
                print(f"❌ Error: {e}")
                results.append({"scenario": scenario, "error": str(e), "status": "error"})

            print("─" * 60)

        return results

# Usage example
async def main():
    """Demo the secure LangChain MCP client."""
    print("🔗 Secure LangChain MCP Client Demo")
    print("=" * 50)
    
    # Load configuration from environment variables
    oauth_config = {
        'token_url': os.environ.get('OAUTH_TOKEN_URL', 'http://localhost:8080/token'),
        'client_id': os.environ.get('OAUTH_CLIENT_ID', 'mcp-secure-client'),
        'client_secret': os.environ.get('OAUTH_CLIENT_SECRET', 'secure-client-secret'),
        'scopes': 'customer:read ticket:create account:calculate',
        'mcp_server_url': os.environ.get('MCP_SERVER_URL', 'http://localhost:8000/mcp'),
        'ca_cert_path': os.environ.get('TLS_CA_CERT_PATH', None)
    }
    
    # Check for OpenAI API key (from environment or .env file)
    openai_api_key = os.environ.get('OPENAI_API_KEY')
    
    if not openai_api_key or openai_api_key == 'your-openai-api-key-here':
        if openai_api_key == 'your-openai-api-key-here':
            print("⚠️  OPENAI_API_KEY is still set to the placeholder value")
            print("   Please update it with your actual API key in the .env file")
        else:
            print("❌ OPENAI_API_KEY not found")
        
        print("\n   Please set it in one of these ways:")
        print("   1. Edit .env file and replace 'your-openai-api-key-here' with your actual key")
        print("   2. Set environment variable: export OPENAI_API_KEY='sk-...'")
        print("   3. Run with: OPENAI_API_KEY='sk-...' python src/secure_clients/langchain_client.py")
        return

    client = SecureLangChainMCPClient(
        openai_api_key=openai_api_key,
        oauth_config=oauth_config
    )

    try:
        # First, check if OAuth server is running
        print("🔍 Checking OAuth server...")
        oauth_url = oauth_config['token_url'].replace('/token', '')
        
        try:
            # Use the same CA verification logic as the main client
            ca_cert_path = oauth_config.get('ca_cert_path', None)
            ssl_cert_file = os.environ.get('SSL_CERT_FILE')
            if ssl_cert_file and os.path.exists(ssl_cert_file):
                ca_cert_path = ssl_cert_file
                
            async with httpx.AsyncClient(verify=ca_cert_path if ca_cert_path else True, timeout=2) as test_client:
                response = await test_client.get(oauth_url)
                print(f"✅ OAuth server is running at {oauth_url}")
        except Exception as e:
            print(f"❌ OAuth server is not accessible at {oauth_url}")
            if oauth_url.startswith('https://'):
                print("   If using Docker, ensure:")
                print("   1. Docker services are running: task docker-up")
                print("   2. Using correct .env file with HTTPS URLs")
            else:
                print("   Please start it first with: task run-oauth")
            print(f"   Error: {str(e)}")
            return
            
        print("🔌 Connecting to secure MCP server...")
        await client.connect_to_secure_mcp_server()
        
        print(f"✅ Connected! Available tools: {len(client.available_tools)}")
        for tool in client.available_tools:
            print(f"   - {tool['name']}")
        
        print("🤖 Setting up LangChain agent...")
        await client.setup_langchain_agent()
        print("✅ LangChain agent ready!")

        # Example customer service scenarios
        scenarios = [
            "Look up customer ABC123 and summarize their account status",
            "Create a high-priority support ticket for customer XYZ789 about billing issues",
            "Calculate account value for customer ABC123 with purchases: [150.0, 300.0, 89.50]",
        ]

        print(f"\n🎭 Running {len(scenarios)} customer service scenarios...")
        results = await client.process_scenarios(scenarios)
        
        # Summary
        successful = len([r for r in results if r.get('status') == 'success'])
        print(f"\n📊 Summary: {successful}/{len(scenarios)} scenarios completed successfully")
                
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\n📋 Make sure both servers are running:")
        print("   1. Start OAuth server: task run-oauth")
        print("   2. Start MCP server in HTTP mode: LLM_PROVIDER=openai task run-server")
        print("   3. Then run this client: python src/secure_clients/langchain_client.py")
        
    finally:
        await client.exit_stack.aclose()

if __name__ == "__main__":
    asyncio.run(main())