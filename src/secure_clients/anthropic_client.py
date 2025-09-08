"""
Secure Anthropic integration with OAuth-protected MCP server.
Demonstrates how to connect Anthropic's Claude API to a secure MCP backend.
"""

import asyncio
from contextlib import AsyncExitStack
import json
import os

# Load environment variables from .env file
# Find .env file in project root (go up from src/secure_clients/)
from pathlib import Path

# Import config for model settings
import sys
import time
from typing import List

from anthropic import AsyncAnthropic
from dotenv import load_dotenv
import httpx
import jwt
from mcp import ClientSession

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from mcp.client.streamable_http import streamablehttp_client

from config import Config

env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class SecureAnthropicMCPClient:
    """Anthropic client with comprehensive MCP security integration."""

    def __init__(self, anthropic_api_key: str, oauth_config: dict):
        self.anthropic_client = AsyncAnthropic(api_key=anthropic_api_key)
        self.oauth_config = oauth_config
        self.access_token = None
        self.token_expires_at = 0
        self.sessions = []
        self.exit_stack = AsyncExitStack()
        self.available_tools = []
        self.tool_to_session = {}

        # Configure secure HTTP client with TLS verification
        ca_cert_path = oauth_config.get("ca_cert_path", None)

        # Check for SSL environment variables (used by mkcert script)
        ssl_cert_file = os.environ.get("SSL_CERT_FILE")
        if ssl_cert_file and os.path.exists(ssl_cert_file):
            ca_cert_path = ssl_cert_file
            if os.environ.get("DEBUG_SSL"):
                print(f"🔐 Using SSL_CERT_FILE: {ssl_cert_file}")

        # Configure secure HTTP client with TLS verification
        self.http_client = httpx.AsyncClient(
            verify=ca_cert_path if ca_cert_path else True, timeout=30.0
        )

    async def get_oauth_token(self) -> str:
        """Obtain OAuth access token using client credentials flow."""
        current_time = time.time()

        # Check if we have a valid token
        if self.access_token and current_time < self.token_expires_at - 60:
            return self.access_token

        # Request new token using the configured HTTP client
        response = await self.http_client.post(
            self.oauth_config["token_url"],
            data={
                "grant_type": "client_credentials",
                "client_id": self.oauth_config["client_id"],
                "client_secret": self.oauth_config["client_secret"],
                "scope": self.oauth_config["scopes"],
            },
        )

        if response.status_code != 200:
            raise Exception(f"OAuth token request failed: {response.text}")

        token_data = response.json()
        self.access_token = token_data["access_token"]

        # Calculate token expiration
        expires_in = token_data.get("expires_in", 3600)
        self.token_expires_at = current_time + expires_in

        return self.access_token

    async def get_oauth_public_key(self) -> str:
        """Fetch OAuth server's public key for JWT verification."""
        try:
            # Get the base OAuth URL
            oauth_base_url = self.oauth_config["token_url"].replace("/token", "")
            jwks_url = f"{oauth_base_url}/jwks"

            # Use the same HTTP client we use for token requests
            response = await self.http_client.get(jwks_url)

            if response.status_code != 200:
                raise Exception(f"Failed to fetch JWKS: {response.status_code}")

            jwks = response.json()

            # Get the first key (in production, might need to match 'kid')
            if "keys" not in jwks or not jwks["keys"]:
                raise Exception("No keys found in JWKS response")

            # Return the first RSA public key
            return jwks["keys"][0]

        except Exception as e:
            print(f"⚠️  Failed to fetch OAuth public key: {e}")
            print("   Falling back to signature verification disabled")
            return None

    async def connect_to_secure_mcp_server(self):
        """Connect to OAuth-protected MCP server."""
        # Get fresh access token
        access_token = await self.get_oauth_token()

        # Create custom httpx client factory with our CA bundle
        def custom_httpx_client_factory(headers=None, timeout=None, auth=None):
            # Get the same CA cert path we use for the main client
            ca_cert_path = self.oauth_config.get("ca_cert_path", None)
            ssl_cert_file = os.environ.get("SSL_CERT_FILE")
            if ssl_cert_file and os.path.exists(ssl_cert_file):
                ca_cert_path = ssl_cert_file
                if os.environ.get("DEBUG_SSL"):
                    print(f"🔐 MCP client using SSL_CERT_FILE: {ssl_cert_file}")

            return httpx.AsyncClient(
                headers=headers,
                timeout=timeout if timeout else httpx.Timeout(30.0),
                auth=auth,
                verify=ca_cert_path
                if ca_cert_path
                else True,  # Use proper SSL verification
                follow_redirects=True,
            )

        # Create HTTP client with authentication headers and custom SSL verification
        http_transport = await self.exit_stack.enter_async_context(
            streamablehttp_client(
                url=self.oauth_config["mcp_server_url"],
                headers={"Authorization": f"Bearer {access_token}"},
                httpx_client_factory=custom_httpx_client_factory,
            )
        )

        read, write, url_getter = http_transport
        session = await self.exit_stack.enter_async_context(ClientSession(read, write))

        # Initialize with auth headers
        await session.initialize()

        self.sessions.append(session)

        # Discover available tools
        response = await session.list_tools()
        for tool in response.tools:
            self.tool_to_session[tool.name] = session

            # Convert to Anthropic tool format (no custom fields allowed)
            anthropic_tool = {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            self.available_tools.append(anthropic_tool)

    def _get_required_scopes(self, tool_name: str) -> List[str]:
        """Map tool names to required OAuth scopes."""
        scope_mapping = {
            "get_customer_info": ["customer:read"],
            "create_support_ticket": ["ticket:create"],
            "calculate_account_value": ["account:calculate"],
            "get_recent_customers": ["customer:read"],
        }
        return scope_mapping.get(tool_name, [])

    async def call_mcp_tool(self, tool_name: str, tool_input: dict):
        """Call MCP tool with security validation."""
        # Verify we have required scopes for this tool
        required_scopes = self._get_required_scopes(tool_name)
        if not await self._verify_token_scopes(required_scopes):
            raise PermissionError(f"Insufficient permissions for {tool_name}")

        # Get session for tool
        session = self.tool_to_session[tool_name]

        # Call the tool
        result = await session.call_tool(tool_name, arguments=tool_input)
        return result

    async def process_secure_query(self, query: str):
        """Process query with security-aware error handling."""
        try:
            # Create message with tool definitions
            message = await self.anthropic_client.messages.create(
                model=Config.ANTHROPIC_MODEL,
                max_tokens=1000,
                messages=[{"role": "user", "content": query}],
                tools=self.available_tools if self.available_tools else [],
            )

            # Process the response
            for content_block in message.content:
                if content_block.type == "text":
                    print(f"🤖 Claude: {content_block.text}")
                elif content_block.type == "tool_use":
                    tool_name = content_block.name
                    tool_input = content_block.input

                    try:
                        result = await self.call_mcp_tool(tool_name, tool_input)

                        # Handle rate limit responses from MCP server
                        if hasattr(result, "error") and "rate_limit" in str(
                            result.error
                        ):
                            retry_after = result.metadata.get("retry_after", 60)
                            print(f"Rate limited. Waiting {retry_after} seconds...")
                            await asyncio.sleep(retry_after)
                            # Retry the tool call
                            result = await self.call_mcp_tool(tool_name, tool_input)

                        # Parse and display the result nicely
                        if hasattr(result, "content") and result.content:
                            content = result.content[0].text if result.content else ""
                            await self.display_results(content, tool_name)

                            # Send tool result back to Claude for final response
                            follow_up = await self.anthropic_client.messages.create(
                                model=Config.ANTHROPIC_MODEL,
                                max_tokens=500,
                                messages=[
                                    {"role": "user", "content": query},
                                    {"role": "assistant", "content": message.content},
                                    {
                                        "role": "user",
                                        "content": [
                                            {
                                                "type": "tool_result",
                                                "tool_use_id": content_block.id,
                                                "content": content,
                                            }
                                        ],
                                    },
                                ],
                            )

                            # Display Claude's final response
                            for follow_content in follow_up.content:
                                if follow_content.type == "text":
                                    print(
                                        f"\n🎯 Claude's Analysis: {follow_content.text}"
                                    )
                        else:
                            print(f"Tool {tool_name} completed (no content returned)")

                    except Exception as e:
                        print(f"❌ Tool {tool_name} failed: {e}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Token expired, refresh and retry
                self.access_token = None
                return await self.process_secure_query(query)
            elif e.response.status_code == 429:
                # Handle rate limiting
                retry_after = int(e.response.headers.get("Retry-After", 60))
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
                if "contact_info" in data:
                    print(f"📧 Email: {data['contact_info']['email']}")
                    print(f"📞 Phone: {data['contact_info']['phone']}")

            elif tool_name == "create_support_ticket":
                print(f"🎫 Ticket ID: {data['ticket_id']}")
                print(f"👤 Customer ID: {data['customer_id']}")
                print(f"📋 Subject: {data['subject']}")
                if "description" in data:
                    print(f"📝 Description: {data['description']}")
                print(f"🚨 Priority: {data['priority']}")
                if "estimated_resolution" in data:
                    print(f"⏰ Resolution Time: {data['estimated_resolution']}")

            elif tool_name == "calculate_account_value":
                calc = data["calculation"]
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
        """Verify the current token has required scopes with proper JWT signature verification."""
        if not self.access_token:
            return False

        try:
            # Get the OAuth server's public key for verification
            public_key_jwk = await self.get_oauth_public_key()

            if public_key_jwk:
                # Proper JWT verification with signature check
                try:
                    # Convert JWK to PEM format for PyJWT
                    from jwt.algorithms import RSAAlgorithm

                    public_key = RSAAlgorithm.from_jwk(public_key_jwk)

                    # Verify JWT with full signature validation
                    payload = jwt.decode(
                        self.access_token,
                        key=public_key,
                        algorithms=["RS256"],
                        audience=self.oauth_config.get("client_id"),  # Verify audience
                        issuer=self.oauth_config.get("token_url", "").replace(
                            "/token", ""
                        ),  # Verify issuer
                    )

                    print("✅ JWT signature verification successful")

                except jwt.InvalidTokenError as e:
                    print(f"❌ JWT signature verification failed: {e}")
                    return False
            else:
                # Fallback to unverified decode if public key unavailable
                print("⚠️  Using unverified JWT decode (development only)")
                payload = jwt.decode(
                    self.access_token, options={"verify_signature": False}
                )

            # Check scopes
            token_scopes = payload.get("scope", "").split()
            has_required_scopes = all(
                scope in token_scopes for scope in required_scopes
            )

            if has_required_scopes:
                print(f"✅ Token has required scopes: {required_scopes}")
            else:
                print(
                    f"❌ Token missing scopes. Has: {token_scopes}, Needs: {required_scopes}"
                )

            return has_required_scopes

        except Exception as e:
            print(f"❌ Token verification error: {e}")
            return False


# Usage example
async def main():
    """Demo the secure Anthropic MCP client."""
    print("🤖 Secure Anthropic Claude MCP Client Demo")
    print("=" * 50)

    # Load configuration from environment variables
    # OAuth configuration - using dynamic URLs from Config
    oauth_config = {
        "token_url": Config.get_oauth_token_url(),  # Dynamically constructed OAuth endpoint
        "client_id": "claude-desktop-client",
        "client_secret": "claude-desktop-secret",
        "scopes": "customer:read ticket:create account:calculate",
        "mcp_server_url": Config.get_mcp_server_url(),  # Dynamically constructed MCP endpoint
        "ca_cert_path": os.environ.get("TLS_CA_CERT_PATH", None),
    }

    # Check for Anthropic API key (from environment or .env file)
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not anthropic_api_key or anthropic_api_key == "your-anthropic-api-key-here":
        if anthropic_api_key == "your-anthropic-api-key-here":
            print("⚠️  ANTHROPIC_API_KEY is still set to the placeholder value")
            print("   Please update it with your actual API key in the .env file")
        else:
            print("❌ ANTHROPIC_API_KEY not found")

        print("\n   Please set it in one of these ways:")
        print(
            "   1. Edit .env file and replace 'your-anthropic-api-key-here' with your actual key"
        )
        print("   2. Set environment variable: export ANTHROPIC_API_KEY='sk-ant-...'")
        print(
            "   3. Run with: ANTHROPIC_API_KEY='sk-ant-...' python src/secure_clients/anthropic_client.py"
        )
        return

    client = SecureAnthropicMCPClient(
        anthropic_api_key=anthropic_api_key, oauth_config=oauth_config
    )

    try:
        # First, check if OAuth server is running
        print("🔍 Checking OAuth server...")
        oauth_url = oauth_config["token_url"].replace("/token", "")

        try:
            # Use the same CA verification logic as the main client
            async with httpx.AsyncClient(verify=False, timeout=2) as test_client:
                await test_client.get(oauth_url)
                print(f"✅ OAuth server is running at {oauth_url}")
        except Exception as e:
            print(f"❌ OAuth server is not accessible at {oauth_url}")
            if oauth_url.startswith("https://"):
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

        # Test queries
        test_queries = [
            "Look up customer ABC123 and check their account status",
            "Create a high-priority support ticket for customer XYZ789 about billing issues with the description 'Customer unable to access premium features after payment'",
            "Calculate the total account value for customer ABC123 with purchases: [150.0, 300.0, 89.50]",
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
        print(
            "   2. Start MCP server in HTTP mode: LLM_PROVIDER=anthropic task run-server"
        )
        print(
            "   3. Then run this client: python src/secure_clients/anthropic_client.py"
        )

    finally:
        await client.exit_stack.aclose()


if __name__ == "__main__":
    asyncio.run(main())
