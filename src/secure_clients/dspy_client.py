"""
Secure DSPy integration with OAuth-protected MCP server.
Demonstrates how to connect DSPy agents to a secure MCP backend.
"""

import asyncio
from contextlib import AsyncExitStack
import os

# Load environment variables from .env file
# Find .env file in project root (go up from src/secure_clients/)
from pathlib import Path

# Import config for model settings
import sys
import time
from typing import List

from dotenv import load_dotenv
import dspy
import httpx
import jwt
from mcp import ClientSession

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from mcp.client.streamable_http import streamablehttp_client

from config import Config

env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


# Define DSPy signatures for customer service tasks
class CustomerServiceSignature(dspy.Signature):
    """Handle customer service requests using available tools."""

    request: str = dspy.InputField(desc="Customer service request")
    response: str = dspy.OutputField(desc="Helpful customer service response")


class SecureDSPyMCPClient:
    """DSPy client with comprehensive MCP security integration."""

    def __init__(self, llm_provider: str, api_key: str, oauth_config: dict):
        self.llm_provider = llm_provider
        self.api_key = api_key
        self.oauth_config = oauth_config
        self.access_token = None
        self.token_expires_at = 0
        self.sessions = []
        self.exit_stack = AsyncExitStack()
        self.available_tools = []
        self.dspy_tools = []
        self.tool_to_session = {}
        self.react_agent = None

        # Configure secure HTTP client with TLS verification

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
            ssl_cert_file = os.environ.get("SSL_CERT_FILE")
            if ssl_cert_file and os.path.exists(ssl_cert_file):
                if os.environ.get("DEBUG_SSL"):
                    print(f"🔐 MCP client using SSL_CERT_FILE: {ssl_cert_file}")

            return httpx.AsyncClient(
                headers=headers,
                timeout=timeout if timeout else httpx.Timeout(30.0),
                auth=auth,
                verify=ssl_cert_file
                if ssl_cert_file and os.path.exists(ssl_cert_file)
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

        read, write, _ = http_transport
        session = await self.exit_stack.enter_async_context(ClientSession(read, write))

        # Initialize with auth headers
        await session.initialize()

        self.sessions.append(session)

        # Discover available tools
        response = await session.list_tools()
        for tool in response.tools:
            self.tool_to_session[tool.name] = session
            self.available_tools.append(tool)

    def _get_required_scopes(self, tool_name: str) -> List[str]:
        """Map tool names to required OAuth scopes."""
        scope_mapping = {
            "get_customer_info": ["customer:read"],
            "create_support_ticket": ["ticket:create"],
            "calculate_account_value": ["account:calculate"],
            "get_recent_customers": ["customer:read"],
        }
        return scope_mapping.get(tool_name, [])

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

    async def setup_dspy_agent(self):
        """Set up DSPy with secure MCP tools."""

        # Configure DSPy with the appropriate language model
        if self.llm_provider == "openai":
            llm_kwargs = {"api_key": self.api_key}
            if Config.OPENAI_BASE_URL:
                llm_kwargs["base_url"] = Config.OPENAI_BASE_URL
            llm = dspy.LM(f"openai/{Config.OPENAI_MODEL}", **llm_kwargs)
        elif self.llm_provider == "anthropic":
            llm = dspy.LM(f"anthropic/{Config.ANTHROPIC_MODEL}", api_key=self.api_key)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")

        dspy.configure(lm=llm)

        # Create DSPy tool wrappers for MCP tools
        class SecureMCPTool:
            """Wrapper to make MCP tools compatible with DSPy."""

            def __init__(self, tool, session, client):
                self.tool = tool
                self.session = session
                self.client = client
                self.name = tool.name
                self.description = tool.description
                self.input_schema = tool.inputSchema

            async def __call__(self, **kwargs):
                """Execute the MCP tool with security validation."""
                # Verify required scopes
                required_scopes = self.client._get_required_scopes(self.name)
                if not await self.client._verify_token_scopes(required_scopes):
                    raise PermissionError(f"Insufficient permissions for {self.name}")

                try:
                    # Call the MCP tool
                    result = await self.session.call_tool(self.name, arguments=kwargs)

                    # Handle rate limit responses
                    if hasattr(result, "error") and "rate_limit" in str(result.error):
                        retry_after = result.metadata.get("retry_after", 60)
                        print(f"⏳ Rate limited. Waiting {retry_after} seconds...")
                        await asyncio.sleep(retry_after)
                        # Retry the tool call
                        result = await self.session.call_tool(
                            self.name, arguments=kwargs
                        )

                    # Extract content from result
                    if hasattr(result, "content") and result.content:
                        return result.content[0].text if result.content else ""
                    else:
                        return f"Tool {self.name} completed successfully"

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 401:
                        # Token expired, refresh and retry
                        self.client.access_token = None
                        await self.client.get_oauth_token()
                        return await self.__call__(**kwargs)
                    elif e.response.status_code == 429:
                        # Handle rate limiting
                        retry_after = int(e.response.headers.get("Retry-After", 60))
                        print(
                            f"⏳ Rate limited by server. Waiting {retry_after} seconds..."
                        )
                        await asyncio.sleep(retry_after)
                        return await self.__call__(**kwargs)
                    else:
                        raise

        # Convert MCP tools to DSPy-compatible tools
        self.dspy_tools = []
        for tool in self.available_tools:
            session = self.tool_to_session[tool.name]
            dspy_tool = SecureMCPTool(tool, session, self)
            self.dspy_tools.append(dspy_tool)

        # Create a ReAct agent with the secure tools
        self.react_agent = dspy.ReAct(
            CustomerServiceSignature, tools=self.dspy_tools, max_iters=5
        )

    async def process_request(self, request: str) -> str:
        """Process a customer service request using DSPy ReAct agent."""
        if not self.react_agent:
            raise RuntimeError("Agent not initialized. Call setup_dspy_agent() first.")

        try:
            # Use DSPy's async call method
            result = await self.react_agent.acall(request=request)
            return result.response
        except Exception as e:
            return f"Error processing request: {str(e)}"

    async def process_scenarios(self, scenarios: List[str]):
        """Process multiple scenarios with the DSPy agent."""
        results = []

        for i, scenario in enumerate(scenarios, 1):
            print(f"\n📝 Scenario {i}: {scenario}")
            try:
                response = await self.process_request(scenario)
                print(f"🤖 DSPy Agent Response: {response}")
                results.append(
                    {"scenario": scenario, "response": response, "status": "success"}
                )
            except Exception as e:
                print(f"❌ Error: {e}")
                results.append(
                    {"scenario": scenario, "error": str(e), "status": "error"}
                )
            print("─" * 60)

        return results


# Usage example
async def main():
    """Demo the secure DSPy MCP client."""
    print("🔮 Secure DSPy MCP Client Demo")
    print("=" * 50)

    # OAuth configuration for Azure OAuth Proxy
    oauth_config = {
        "token_url": "https://localhost:8443/token",  # Azure OAuth Proxy endpoint
        "client_id": "mcp-secure-client",
        "client_secret": "secure-client-secret",
        "scopes": "customer:read ticket:create account:calculate",
        "mcp_server_url": os.environ.get("MCP_SERVER_URL", "http://localhost:8000/mcp"),
        "ca_cert_path": os.environ.get("TLS_CA_CERT_PATH", None),
    }

    # Determine LLM provider and API key
    llm_provider = os.environ.get("LLM_PROVIDER", "openai")

    if llm_provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key or api_key == "your-openai-api-key-here":
            print("❌ OPENAI_API_KEY not found or using placeholder")
            print("\n   Please set it in one of these ways:")
            print(
                "   1. Edit .env file and replace 'your-openai-api-key-here' with your actual key"
            )
            print("   2. Set environment variable: export OPENAI_API_KEY='sk-...'")
            print(
                "   3. Run with: OPENAI_API_KEY='sk-...' python src/secure_clients/dspy_client.py"
            )
            return
    elif llm_provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key or api_key == "your-anthropic-api-key-here":
            print("❌ ANTHROPIC_API_KEY not found or using placeholder")
            print("\n   Please set it in one of these ways:")
            print(
                "   1. Edit .env file and replace 'your-anthropic-api-key-here' with your actual key"
            )
            print(
                "   2. Set environment variable: export ANTHROPIC_API_KEY='sk-ant-...'"
            )
            print(
                "   3. Run with: ANTHROPIC_API_KEY='sk-ant-...' python src/secure_clients/dspy_client.py"
            )
            return
    else:
        print(f"❌ Unsupported LLM provider: {llm_provider}")
        print("   DSPy requires either 'openai' or 'anthropic' as LLM_PROVIDER")
        return

    client = SecureDSPyMCPClient(
        llm_provider=llm_provider, api_key=api_key, oauth_config=oauth_config
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
            print(f"   - {tool.name}: {tool.description}")

        print("🤖 Setting up DSPy agent...")
        await client.setup_dspy_agent()
        print("✅ DSPy agent ready!")

        # Example customer service scenarios
        scenarios = [
            "For customer ABC123 create a support ticket as the bbq grill that she bought is defective.",
            "Check the account status for customer ABC123 and calculate their total purchase value with amounts [250.0, 175.50, 82.25]",
            "Calculate account value for customer ABC123 with purchases: $150.0, $300.0 and $89.50",
        ]

        print(f"\n🎯 Running {len(scenarios)} customer service scenarios...")
        results = await client.process_scenarios(scenarios)

        # Summary
        successful = len([r for r in results if r.get("status") == "success"])
        print(
            f"\n📊 Summary: {successful}/{len(scenarios)} scenarios completed successfully"
        )

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\n📋 Make sure both servers are running:")
        print("   1. Start OAuth server: task run-oauth")
        print(
            f"   2. Start MCP server in HTTP mode: LLM_PROVIDER={llm_provider} task run-server"
        )
        print("   3. Then run this client: python src/secure_clients/dspy_client.py")

    finally:
        await client.exit_stack.aclose()


if __name__ == "__main__":
    asyncio.run(main())
