"""LiteLLM integration with secure MCP server."""

import asyncio
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

from dotenv import load_dotenv
import httpx
import jwt
import litellm
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from config import Config

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Load environment variables
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class LiteLLMMCPClient:
    """LiteLLM client with secure MCP integration."""

    def __init__(self, oauth_config: dict):
        """Initialize the LiteLLM MCP client."""
        self.oauth_config = oauth_config
        self.access_token = None
        self.token_expires_at = 0
        self.session = None
        self.tools = []
        self.exit_stack = AsyncExitStack()

        # Configure secure HTTP client with TLS verification
        ca_cert_path = oauth_config.get("ca_cert_path", None)

        # Check for SSL environment variables (used by mkcert script)
        ssl_cert_file = os.environ.get("SSL_CERT_FILE")
        if ssl_cert_file and os.path.exists(ssl_cert_file):
            ca_cert_path = ssl_cert_file

        self.http_client = httpx.AsyncClient(
            verify=ca_cert_path if ca_cert_path else True
        )

    async def get_oauth_token(self) -> str:
        """Obtain OAuth access token using client credentials flow."""
        current_time = time.time()

        # Check if we have a valid token
        if self.access_token and current_time < self.token_expires_at - 60:
            return self.access_token

        # Request new token
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

        print("✅ OAuth authentication successful")
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

    def _get_required_scopes(self, tool_name: str) -> List[str]:
        """Map tool names to required OAuth scopes."""
        scope_mapping = {
            "get_customer_info": ["customer:read"],
            "create_support_ticket": ["ticket:create"],
            "calculate_account_value": ["account:calculate"],
            "get_recent_customers": ["customer:read"],
        }
        return scope_mapping.get(tool_name, [])

    async def setup_mcp_connection(self):
        """Set up HTTP MCP server connection."""
        print("🔗 Connecting to MCP server via HTTP...")
        print(f"   MCP URL: {self.oauth_config['mcp_server_url']}")

        try:
            # Custom HTTP client factory for SSL handling
            def custom_httpx_client_factory(headers=None, timeout=None, auth=None):
                # Get SSL certificate path from environment variables
                ssl_cert_file = os.environ.get("SSL_CERT_FILE")
                verify_setting = (
                    ssl_cert_file
                    if ssl_cert_file and os.path.exists(ssl_cert_file)
                    else True
                )

                return httpx.AsyncClient(
                    headers=headers,
                    timeout=timeout if timeout else httpx.Timeout(30.0),
                    auth=auth,
                    verify=verify_setting,  # Use proper SSL verification
                    follow_redirects=True,
                )

            # Create HTTP MCP client with authentication
            transport = await self.exit_stack.enter_async_context(
                streamablehttp_client(
                    url=self.oauth_config["mcp_server_url"],
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    httpx_client_factory=custom_httpx_client_factory,
                )
            )

            read, write, url_getter = transport
            session = await self.exit_stack.enter_async_context(
                ClientSession(read, write)
            )

            # Initialize the MCP connection
            await session.initialize()
            self.session = session

            # Get available tools
            list_tools_result = await session.list_tools()
            print(f"📋 Found {len(list_tools_result.tools)} MCP tools")

            # Convert MCP tools to OpenAI function format
            self.tools = []
            for tool in list_tools_result.tools:
                openai_tool = {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": tool.inputSchema
                        or {"type": "object", "properties": {}},
                    },
                }
                self.tools.append(openai_tool)

            print(f"🔧 Converted {len(self.tools)} tools to OpenAI format")
            return session, transport

        except Exception as e:
            print(f"❌ Failed to connect to MCP server: {e}")
            raise

    async def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool through real MCP connection with security validation."""
        if not self.session:
            raise Exception("MCP session not initialized")

        # Verify we have required scopes for this tool
        required_scopes = self._get_required_scopes(tool_name)
        if not await self._verify_token_scopes(required_scopes):
            raise PermissionError(f"Insufficient permissions for {tool_name}")

        try:
            print(f"   🔧 Executing {tool_name} with {arguments}")
            result = await self.session.call_tool(tool_name, arguments)

            # Debug: Print the actual result structure
            print(f"   🔍 Debug - Result type: {type(result)}")
            print(
                f"   🔍 Debug - Result content: {result.content if hasattr(result, 'content') else 'No content attr'}"
            )

            # Extract content from MCP result
            if hasattr(result, "content") and result.content:
                if isinstance(result.content, list) and len(result.content) > 0:
                    # Get the text content from the first content item
                    content_item = result.content[0]
                    if hasattr(content_item, "text"):
                        content = content_item.text
                        print(f"   🔍 Debug - Extracted text: {content[:100]}...")
                        return content
                    else:
                        content = str(content_item)
                        print(f"   🔍 Debug - Stringified content: {content[:100]}...")
                        return content
                else:
                    content = str(result.content)
                    print(f"   🔍 Debug - Raw content: {content[:100]}...")
                    return content
            else:
                print("   🔍 Debug - No content found, using default message")
                return f"Tool {tool_name} executed successfully"

        except Exception as e:
            print(f"❌ Tool execution failed for {tool_name}: {e}")
            return f"Error executing {tool_name}: {str(e)}"

    async def chat_with_tools(
        self, messages: List[Dict[str, str]], model: str = None
    ) -> str:
        """Chat with LiteLLM using MCP tools."""
        if not model:
            model = (
                Config.OPENAI_MODEL
                if Config.LLM_PROVIDER == "openai"
                else Config.ANTHROPIC_MODEL
            )

        print(f"🤖 Using model: {model}")
        print(f"💬 Starting conversation with {len(self.tools)} available tools")

        try:
            # First call to get tool requests
            response = await litellm.acompletion(
                model=model,
                messages=messages,
                tools=self.tools if self.tools else None,
                tool_choice="auto" if self.tools else None,
            )

            # Extract the response
            message = response.choices[0].message

            # Check if the model made tool calls
            if hasattr(message, "tool_calls") and message.tool_calls:
                print(f"🔧 Model requested {len(message.tool_calls)} tool calls")

                # Add assistant's message with tool calls to conversation
                messages.append(
                    {
                        "role": "assistant",
                        "content": message.content or "",
                        "tool_calls": [
                            {
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.function.name,
                                    "arguments": call.function.arguments,
                                },
                            }
                            for call in message.tool_calls
                        ],
                    }
                )

                # Execute each tool call
                for call in message.tool_calls:
                    print(f"   ⚡ Executing {call.function.name}")

                    try:
                        # Parse arguments
                        arguments = json.loads(call.function.arguments)

                        # Execute the tool through MCP
                        result = await self.execute_tool(call.function.name, arguments)

                        # Add tool result to conversation
                        messages.append(
                            {
                                "role": "tool",
                                "content": str(result),
                                "tool_call_id": call.id,
                            }
                        )

                        print(f"   ✅ Tool {call.function.name} executed successfully")

                    except Exception as e:
                        print(f"   ❌ Tool {call.function.name} failed: {e}")
                        messages.append(
                            {
                                "role": "tool",
                                "content": f"Error: {str(e)}",
                                "tool_call_id": call.id,
                            }
                        )

                # Get final response from model with tool results
                final_response = await litellm.acompletion(
                    model=model,
                    messages=messages,
                    tools=self.tools if self.tools else None,
                )

                return final_response.choices[0].message.content or "No response"

            else:
                # No tool calls, return direct response
                return message.content or "No response"

        except Exception as e:
            print(f"❌ Chat completion failed: {e}")
            return f"Error: {str(e)}"

    async def run_demo(self):
        """Run a comprehensive demo of LiteLLM with MCP tools."""
        print("🚀 Starting LiteLLM MCP Demo")
        print("=" * 50)

        try:
            # Set up OAuth authentication
            await self.get_oauth_token()

            # Connect to real MCP server
            await self.setup_mcp_connection()

            # Test scenarios
            scenarios = [
                {
                    "name": "Customer Account Calculation",
                    "messages": [
                        {
                            "role": "user",
                            "content": "Customer CUST67890 recently made purchases of $150, $300, $13 and $89. Calculate their total account value and check if they qualify for premium status (>$500).",
                        }
                    ],
                },
                {
                    "name": "User Information Lookup",
                    "messages": [
                        {
                            "role": "user",
                            "content": "Look up information for customer 'JOHNDOE123' and tell me about their account status.",
                        }
                    ],
                },
            ]

            # Test with different models if available
            models_to_test = []
            if Config.LLM_PROVIDER == "openai" and Config.OPENAI_API_KEY:
                models_to_test.append(Config.OPENAI_MODEL)
            if Config.LLM_PROVIDER == "anthropic" and Config.ANTHROPIC_API_KEY:
                models_to_test.append(Config.ANTHROPIC_MODEL)

            if not models_to_test:
                if Config.OPENAI_API_KEY:
                    models_to_test.append(Config.OPENAI_MODEL)
                elif Config.ANTHROPIC_API_KEY:
                    models_to_test.append(Config.ANTHROPIC_MODEL)

            for model in models_to_test:
                print(f"\n🧪 Testing with {model}")
                print("-" * 30)

                for scenario in scenarios:
                    print(f"\n📝 Scenario: {scenario['name']}")
                    print(f"🙋 User: {scenario['messages'][0]['content']}")

                    try:
                        response = await self.chat_with_tools(
                            scenario["messages"].copy(), model=model
                        )
                        print(f"🤖 Assistant: {response}")

                    except Exception as e:
                        print(f"❌ Error in scenario '{scenario['name']}': {e}")

                print()

        except Exception as e:
            print(f"❌ Demo failed: {e}")
            raise
        finally:
            # Clean up connections
            if hasattr(self, "exit_stack"):
                await self.exit_stack.aclose()
            if hasattr(self, "http_client"):
                await self.http_client.aclose()


async def main():
    """Main entry point for LiteLLM MCP client."""
    # Validate configuration
    Config.validate()

    # Check API keys
    if Config.LLM_PROVIDER == "openai" and not Config.OPENAI_API_KEY:
        print("❌ OPENAI_API_KEY not found")
        print("   Please set it in .env file or as environment variable")
        return
    elif Config.LLM_PROVIDER == "anthropic" and not Config.ANTHROPIC_API_KEY:
        print("❌ ANTHROPIC_API_KEY not found")
        print("   Please set it in .env file or as environment variable")
        return

    # OAuth configuration - use environment settings
    oauth_config = {
        "token_url": os.environ.get("OAUTH_TOKEN_URL", "https://localhost:8443/token"),
        "client_id": os.environ.get("OAUTH_CLIENT_ID", "openai-mcp-client"),
        "client_secret": os.environ.get("OAUTH_CLIENT_SECRET", "openai-client-secret"),
        "scopes": "customer:read ticket:create account:calculate",
        "mcp_server_url": os.environ.get(
            "MCP_SERVER_URL", "https://localhost:8001/mcp/"
        ),
        "ca_cert_path": os.environ.get("TLS_CA_CERT_PATH", None),
    }

    print("🔍 Checking OAuth server availability...")
    print(f"   Token URL: {oauth_config['token_url']}")

    # Test OAuth server connectivity first (disable SSL verification for self-signed certs)
    try:
        async with httpx.AsyncClient(verify=False) as test_client:
            # Extract base URL from token URL
            base_url = oauth_config["token_url"].replace("/token", "")
            response = await test_client.get(base_url)
            if response.status_code not in [
                200,
                404,
            ]:  # 404 is ok, means server is running
                print("⚠️  OAuth server may not be running")
                print("   Please start it with: task docker-up")
                return
    except Exception as e:
        print("⚠️  OAuth server not available")
        print("   Please start it with: task docker-up")
        print(f"   Error: {e}")
        return

    # Create and run the client
    client = LiteLLMMCPClient(oauth_config)
    await client.run_demo()


if __name__ == "__main__":
    asyncio.run(main())
