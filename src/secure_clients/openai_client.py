"""
Secure OpenAI integration with OAuth-protected MCP server.
Demonstrates how to connect OpenAI's chat API to a secure MCP backend.
"""

import asyncio
import json
import time
import os
from typing import Dict, List, Optional
import httpx
from contextlib import AsyncExitStack
from dotenv import load_dotenv

from openai import AsyncOpenAI
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

class SecureOpenAIMCPClient:
    """OpenAI client with comprehensive MCP security integration."""
    
    def __init__(self, openai_api_key: str, oauth_config: dict):
        self.openai_client = AsyncOpenAI(api_key=openai_api_key)
        self.oauth_config = oauth_config
        self.access_token = None
        self.token_expires_at = 0
        self.sessions = []
        self.exit_stack = AsyncExitStack()
        self.available_tools = []
        self.tool_to_session = {}

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

            # Convert to OpenAI function format with security context
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema,
                    "x-oauth-scopes": self._get_required_scopes(tool.name)
                }
            }
            self.available_tools.append(openai_tool)

    def _get_required_scopes(self, tool_name: str) -> List[str]:
        """Map tool names to required OAuth scopes."""
        scope_mapping = {
            "get_customer_info": ["customer:read"],
            "create_support_ticket": ["ticket:create"],
            "calculate_account_value": ["account:calculate"],
            "get_recent_customers": ["customer:read"]
        }
        return scope_mapping.get(tool_name, [])

    async def call_mcp_tool(self, tool_call, tool_name):
        # Verify we have required scopes for this tool
        required_scopes = self._get_required_scopes(tool_name)
        if not await self._verify_token_scopes(required_scopes):
            raise PermissionError(
                f"Insufficient permissions for {tool_name}"
            )
        # Get session for tool
        session = self.tool_to_session[tool_name]
        # Note: With HTTP transport, auth is handled via headers during connection
        # Call the tool
        tool_args = json.loads(tool_call.function.arguments)
        result = await session.call_tool(
            tool_name,
            arguments=tool_args
        )
        return result


    async def process_secure_query(self, query: str):
        """Process query with security-aware error handling."""
        messages = [{"role": "user", "content": query}]

        try:
            response = await self.openai_client.chat.completions.create(
                model=Config.OPENAI_MODEL,
                messages=messages,
                tools=self.available_tools if self.available_tools else None,
                tool_choice="auto"
            )

            # Handle tool calls with security checks
            if response.choices[0].message.tool_calls:
                for tool_call in response.choices[0].message.tool_calls:
                    tool_name = tool_call.function.name

                    result = await self.call_mcp_tool(tool_call, tool_name)

                    # Handle rate limit responses from MCP server
                    if hasattr(result, 'error') and 'rate_limit' in str(result.error):
                        retry_after = result.metadata.get('retry_after', 60)
                        print(f"Rate limited. Waiting {retry_after} seconds...")
                        await asyncio.sleep(retry_after)
                        # Retry the tool call
                        result = await self.call_mcp_tool(tool_call, tool_name)


                    # Parse and display the result nicely
                    if hasattr(result, 'content') and result.content:
                        content = result.content[0].text if result.content else ""
                        await self.display_results(content, tool_name)
                    else:
                        print(f"Tool {tool_name} completed (no content returned)")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Token expired, refresh and retry
                self.access_token = None
                return await self.process_secure_query(query)
            elif e.response.status_code == 429:
                # Handle rate limiting
                retry_after = int(e.response.headers.get('Retry-After', 60))
                print(f"Rate limited by server. Waiting {retry_after} seconds...")
                await asyncio.sleep(retry_after)
                return await self.process_secure_query(query)
            else:
                raise

    @staticmethod
    async def display_results(content, tool_name):
        try:
            # Parse JSON result
            data = json.loads(content)

            print(f"\n🔧 Tool: {tool_name}")
            print("─" * 50)

            # Format based on tool type
            if tool_name == "get_customer_info":
                print(f"👤 Customer ID: {data['customer_id']}")
                print(f"📛 Name: {data['name']}")
                print(f"✅ Status: {data['status']}")
                print(f"💎 Account Type: {data['account_type']}")
                print(f"📧 Email: {data['contact_info']['email']}")
                print(f"📞 Phone: {data['contact_info']['phone']}")

            elif tool_name == "create_support_ticket":
                print(f"🎫 Ticket ID: {data['ticket_id']}")
                print(f"👤 Customer ID: {data['customer_id']}")
                print(f"📋 Subject: {data['subject']}")
                print(f"📝 Description: {data['description']}")
                print(f"🚨 Priority: {data['priority']}")
                print(f"⏰ Resolution Time: {data['estimated_resolution']}")

            elif tool_name == "calculate_account_value":
                calc = data['calculation']
                print(f"👤 Customer ID: {data['customer_id']}")
                print(f"💰 Total Value: ${calc['total']:,.2f}")
                print(f"📊 Average Purchase: ${calc['average']:,.2f}")
                print(f"🛍️ Number of Purchases: {calc['count']}")
                print(f"📈 Highest Purchase: ${calc['max_purchase']:,.2f}")
                print(f"📉 Lowest Purchase: ${calc['min_purchase']:,.2f}")
                print(f"🏆 Account Tier: {data['account_tier'].upper()}")

            print("─" * 50)

        except json.JSONDecodeError:
            # Fall back to raw display if not JSON
            print(f"Tool {tool_name} result: {content}")


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

# Usage example
async def main():
    """Demo the secure OpenAI MCP client."""
    print("🤖 Secure OpenAI MCP Client Demo")
    print("=" * 50)
    
    # Load configuration from environment variables
    oauth_config = {
        'token_url': os.environ.get('OAUTH_TOKEN_URL', 'http://localhost:8080/token'),
        'client_id': os.environ.get('OAUTH_CLIENT_ID', 'openai-mcp-client'),
        'client_secret': os.environ.get('OAUTH_CLIENT_SECRET', 'openai-client-secret'),
        'scopes': 'customer:read ticket:create account:calculate',
        'mcp_server_url': os.environ.get('MCP_SERVER_URL', 'http://localhost:8000/mcp'),
        'ca_cert_path': os.environ.get('TLS_CA_CERT_PATH', None)  # For demo, disable TLS verification
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
        print("   3. Run with: OPENAI_API_KEY='sk-...' task run-openai-client")
        return

    client = SecureOpenAIMCPClient(
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
            print(f"   - {tool['function']['name']}")
        
        # Test queries
        test_queries = [
            "Look up customer 12345 and check their account status",
            "Create a high-priority support ticket for customer 67890 about billing issues",
            "Calculate the total account value for customer 12345 with purchases: $150, $300, $89"
        ]
        
        for i, query in enumerate(test_queries, 1):
            print(f"\n📝 Test Query {i}: {query}")
            try:
                await client.process_secure_query(query)
                print("✅ Query processed successfully")
            except Exception as e:
                print(f"❌ Query failed: {e}")
                
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\n📋 Make sure both servers are running:")
        print("   1. Start OAuth server: task run-oauth")
        print("   2. Start MCP server in HTTP mode: LLM_PROVIDER=openai task run-server")
        print("   3. Then run this client: task run-openai-client")
        
    finally:
        await client.exit_stack.aclose()

if __name__ == "__main__":
    asyncio.run(main())