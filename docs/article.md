# Securing MCP: From Vulnerable to Fortified — Building Secure HTTP-based AI Integrations

Imagine leaving your house with all doors and windows wide open, valuables in plain sight, and a sign saying "Come on in!" That's essentially what many developers do when deploying Model Context Protocol (MCP) servers without proper security. As MCP adoption explodes in 2025, the rush to connect AI systems to external tools has created a perfect storm of security vulnerabilities. But here's the good news: securing your MCP implementation doesn't require a PhD in cryptography — it just needs the right approach.

In this guide, we'll transform your MCP server from an open invitation to hackers into a fortified digital fortress. We'll explore real-world security patterns, implement bulletproof authentication, and show you how to protect your AI integrations from the threats lurking in production environments. By the end, you'll have a complete security toolkit for building MCP servers that are both powerful and protected.

## The Security Nightmare That Keeps Developers Awake

Before MCP, integrating AI with external systems was complex enough. Now, as we expose these integrations over HTTP, we've inherited every web security vulnerability known to humanity — plus some new ones unique to AI systems. Recent security audits reveal a shocking statistic: **43% of MCP servers in production have critical command injection vulnerabilities**. That's nearly half of all deployments sitting vulnerable to attack.

Picture this scenario: You've built a brilliant customer service MCP server that queries databases, creates tickets, and processes payments. Without proper security, an attacker could manipulate your AI to:

- Extract your entire customer database through crafted prompts
- Execute arbitrary commands on your server
- Hijack user sessions and impersonate legitimate users
- Launch denial-of-service attacks that drain your resources
- Inject malicious responses that corrupt your AI's behavior

The transition from local MCP deployments to HTTP-based production systems introduces what security experts call the "attack surface explosion." Every endpoint, every parameter, and every connection becomes a potential entry point for malicious actors.

## Understanding the Threat Landscape: What Makes MCP Different

MCP's unique architecture creates security challenges that traditional web applications don't face. When you combine AI's unpredictability with HTTP's openness, you get a cocktail of vulnerabilities that require special attention.

**The AI Factor** makes MCP security particularly challenging. Unlike traditional APIs with predictable inputs and outputs, MCP servers must handle dynamic tool invocations from AI models that might be influenced by clever prompt engineering. An attacker doesn't need to hack your server directly — they just need to trick your AI into doing it for them.

**The Tool Execution Problem** represents another unique challenge. MCP servers execute functions based on AI decisions, creating a new class of confused deputy attacks where the server can't distinguish between legitimate AI requests and malicious manipulations. Without proper validation, your helpful AI assistant becomes an unwitting accomplice to security breaches.

**The Session State Challenge** compounds these issues. MCP's Streamable HTTP transport maintains stateful sessions across multiple requests, creating opportunities for session hijacking and replay attacks that persist longer than traditional stateless API calls.

## Building Your Security Foundation: The Four Pillars

Just as a fortress needs walls, gates, guards, and surveillance, your MCP server needs four fundamental security pillars to stay protected.

### Pillar 1: Authentication and Authorization — Your Digital Identity Check

Modern MCP security starts with **OAuth 2.1 with PKCE** (Proof Key for Code Exchange). This isn't just a recommendation — as of March 2025, it's mandatory for all HTTP-based MCP servers. Think of PKCE as a special handshake that proves both parties are who they claim to be, even if someone's watching.

Here's how to implement OAuth 2.1 in your FastMCP server:

```python
from fastmcp import FastMCP
from fastapi import Depends, HTTPException, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
import jwt
from datetime import datetime, timedelta

# Initialize FastMCP with security
mcp = FastMCP("Secure Customer Service")

# OAuth2 configuration with PKCE support
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://auth.example.com/authorize",
    tokenUrl="https://auth.example.com/token",
    scopes={
        "customer:read": "Read customer data",
        "ticket:create": "Create support tickets",
        "account:calculate": "Calculate account values"
    }
)

# JWT validation with proper secret management
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")  # Never hardcode!
ALGORITHM = "RS256"  # Use asymmetric encryption

async def validate_token(token: str = Depends(oauth2_scheme)):
    """Validate JWT tokens with proper claims verification."""
    try:
        # Decode and verify the token
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_aud": True, "verify_iss": True}
        )

        # Check token expiration
        if datetime.fromtimestamp(payload['exp']) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Token expired")

        # Verify required scopes
        token_scopes = payload.get("scope", "").split()
        return {"user_id": payload["sub"], "scopes": token_scopes}

    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Secure MCP resource with authentication
@mcp.resource("customer://{customer_id}")
async def get_customer_info(
    customer_id: str,
    auth: dict = Depends(validate_token)
):
    """Retrieve customer information with proper authorization."""
    # Check if user has required scope
    if "customer:read" not in auth["scopes"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Log access for audit trail
    logger.info(f"User {auth['user_id']} accessed customer {customer_id}")

    # ... rest of implementation

```

### Pillar 2: Transport Security — Your Encrypted Highway

Think of TLS (Transport Layer Security) as an armored vehicle for your data. Without it, every piece of information travels in plain sight, readable by anyone monitoring the network. For MCP servers, **TLS 1.2 is the absolute minimum**, with TLS 1.3 strongly recommended.

Here's how to configure proper TLS for your MCP deployment:

```python
# nginx.conf for MCP server with proper TLS configuration
server {
    listen 443 ssl http2;
    server_name mcp.example.com;

    # Strong SSL configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;

    # TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites for TLS 1.3
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;

    # Enable OCSP stapling for better performance
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'none'; connect-src 'self'" always;

    # Proxy to MCP server
    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

```

### Pillar 3: Input Validation — Your Security Scanner

Every input to your MCP server is a potential weapon in an attacker's arsenal. Command injection vulnerabilities affect nearly half of all MCP implementations because developers trust AI-generated inputs too much. Here's how to implement bulletproof validation:

```python
from pydantic import BaseModel, validator, constr
import re
import bleach

class SecureTicketRequest(BaseModel):
    customer_id: constr(regex="^[A-Z0-9]{5,10}$")  # Strict ID format
    subject: constr(min_length=1, max_length=200)
    description: constr(min_length=1, max_length=2000)
    priority: str

    @validator('subject', 'description')
    def sanitize_text(cls, v):
        """Remove any potential injection attempts."""
        # Strip HTML and dangerous characters
        cleaned = bleach.clean(v, tags=[], strip=True)

        # Prevent command injection patterns
        dangerous_patterns = [
            r'\$\{.*\}',  # Template injection
            r'`.*`',      # Command substitution
            r'\|',        # Pipe commands
            r'&&',        # Command chaining
            r';',         # Command separation
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, cleaned):
                raise ValueError(f"Invalid characters detected")

        return cleaned

    @validator('priority')
    def validate_priority(cls, v):
        """Ensure priority is from allowed list."""
        allowed_priorities = ['low', 'normal', 'high', 'urgent']
        if v not in allowed_priorities:
            raise ValueError(f"Priority must be one of {allowed_priorities}")
        return v

@mcp.tool()
async def create_support_ticket(
    request: SecureTicketRequest,
    auth: dict = Depends(validate_token)
):
    """Create ticket with comprehensive validation."""
    # Additional runtime validation
    if not request.customer_id.isalnum():
        raise ValueError("Invalid customer ID format")

    # Use parameterized queries for database operations
    # NEVER use string concatenation or f-strings for SQL!
    query = "INSERT INTO tickets (customer_id, subject, description, priority) VALUES (?, ?, ?, ?)"
    params = (request.customer_id, request.subject, request.description, request.priority)

    # ... execute query safely

```

### Pillar 4: Rate Limiting — Your Traffic Controller

AI operations are expensive, and attackers know it. Without rate limiting, a malicious actor can drain your resources faster than you can say "token limit exceeded." Here's how to implement intelligent rate limiting for MCP:

```python
from fastapi import Request
from fastapi.responses import JSONResponse
import redis
import time
from typing import Optional

# Redis client for distributed rate limiting
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

class RateLimiter:
    def __init__(self, requests_per_minute: int = 60,
                 token_limit_per_hour: int = 100000):
        self.requests_per_minute = requests_per_minute
        self.token_limit_per_hour = token_limit_per_hour

    async def check_rate_limit(self, user_id: str,
                              estimated_tokens: int = 0) -> Optional[dict]:
        """Check both request and token-based rate limits."""
        current_time = int(time.time())

        # Request rate limiting with sliding window
        request_key = f"rate_limit:requests:{user_id}"
        pipe = redis_client.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(request_key, 0, current_time - 60)
        # Add current request
        pipe.zadd(request_key, {str(current_time): current_time})
        # Count requests in window
        pipe.zcard(request_key)
        # Set expiry
        pipe.expire(request_key, 60)

        results = pipe.execute()
        request_count = results[2]

        if request_count > self.requests_per_minute:
            return {
                "error": "Rate limit exceeded",
                "retry_after": 60,
                "limit_type": "requests"
            }

        # Token-based rate limiting for AI operations
        if estimated_tokens > 0:
            token_key = f"rate_limit:tokens:{user_id}:{current_time // 3600}"
            current_tokens = int(redis_client.get(token_key) or 0)

            if current_tokens + estimated_tokens > self.token_limit_per_hour:
                return {
                    "error": "Token limit exceeded",
                    "retry_after": 3600 - (current_time % 3600),
                    "limit_type": "tokens",
                    "remaining": self.token_limit_per_hour - current_tokens
                }

            # Increment token count
            redis_client.incrby(token_key, estimated_tokens)
            redis_client.expire(token_key, 3600)

        return None

# Apply rate limiting to MCP tools
rate_limiter = RateLimiter()

@mcp.tool()
async def analyze_customer_sentiment(
    text: str,
    auth: dict = Depends(validate_token)
):
    """Analyze sentiment with rate limiting."""
    # Estimate tokens based on text length
    estimated_tokens = len(text.split()) * 2

    # Check rate limits
    rate_limit_result = await rate_limiter.check_rate_limit(
        auth["user_id"],
        estimated_tokens
    )

    if rate_limit_result:
        raise HTTPException(
            status_code=429,
            detail=rate_limit_result,
            headers={"Retry-After": str(rate_limit_result["retry_after"])}
        )

    # ... perform sentiment analysis

```

## Putting It All Together: A Secure MCP Implementation

Now let's combine all these security measures into a production-ready MCP server that would make any security auditor smile:

```python
import asyncio
import logging
from datetime import datetime
from typing import List, Optional
import os

from fastmcp import FastMCP
from fastapi import Depends, HTTPException, Security, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel, validator, constr
import jwt
import redis
import bleach
import re

# Configure logging with security events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger("security")

# Initialize secure FastMCP server
mcp = FastMCP("Secure Customer Service")

# Security configuration from environment
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY must be set in environment")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# OAuth2 setup with PKCE
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=os.environ.get("OAUTH_AUTH_URL"),
    tokenUrl=os.environ.get("OAUTH_TOKEN_URL"),
    scopes={
        "customer:read": "Read customer data",
        "ticket:create": "Create support tickets",
        "account:calculate": "Calculate account values"
    }
)

# ... (include all the security implementations from above)

# Add security monitoring
@mcp.on_event("startup")
async def startup_security_checks():
    """Perform security checks on startup."""
    # Verify TLS configuration
    if not os.environ.get("FORCE_HTTPS", "true").lower() == "true":
        security_logger.warning("HTTPS not enforced - security risk!")

    # Check for security headers
    required_env_vars = ["JWT_SECRET_KEY", "OAUTH_AUTH_URL", "OAUTH_TOKEN_URL"]
    for var in required_env_vars:
        if not os.environ.get(var):
            raise ValueError(f"Required security variable {var} not set")

    security_logger.info("Security checks passed")

# Add request logging for audit trail
@mcp.middleware("http")
async def security_audit_middleware(request: Request, call_next):
    """Log all requests for security audit."""
    start_time = time.time()

    # Log request
    security_logger.info(f"Request: {request.method} {request.url.path} from {request.client.host}")

    # Process request
    response = await call_next(request)

    # Log response
    process_time = time.time() - start_time
    security_logger.info(f"Response: {response.status_code} in {process_time:.3f}s")

    # Add security headers to response
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    return response

if __name__ == "__main__":
    # Run with proper security configuration
    import uvicorn

    uvicorn.run(
        "main:mcp.app",
        host="127.0.0.1",  # Only bind to localhost
        port=8000,
        ssl_keyfile="path/to/key.pem",
        ssl_certfile="path/to/cert.pem",
        ssl_version=3,  # TLS 1.2 minimum
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "filename": "mcp_security.log",
                    "maxBytes": 10485760,  # 10MB
                    "backupCount": 5,
                    "formatter": "default",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["file"],
            },
        }
    )

```

## Security Checklist: Your Pre-Flight Safety Check

Before deploying your MCP server to production, run through this comprehensive security checklist:

**Authentication & Authorization**

- ✓ OAuth 2.1 with PKCE implemented
- ✓ JWT tokens use RS256 or ES256 (never HS256 in production)
- ✓ Token expiration set to 15-60 minutes
- ✓ Refresh token rotation implemented
- ✓ Scopes properly defined and enforced

**Transport Security**

- ✓ TLS 1.2 minimum, TLS 1.3 preferred
- ✓ Strong cipher suites configured
- ✓ HSTS header with minimum 1-year max-age
- ✓ Certificate pinning for critical connections
- ✓ No mixed content or protocol downgrades

**Input Validation**

- ✓ All inputs validated with Pydantic models
- ✓ Dangerous patterns blocked with regex
- ✓ SQL queries use parameterization exclusively
- ✓ File uploads restricted and scanned
- ✓ Command execution uses allowlists only

**Rate Limiting & DDoS Protection**

- ✓ Request rate limiting implemented
- ✓ Token-based limits for AI operations
- ✓ Distributed rate limiting with Redis
- ✓ Proper 429 responses with Retry-After
- ✓ CDN or WAF protection enabled

**Monitoring & Incident Response**

- ✓ Security events logged with correlation IDs
- ✓ Failed authentication attempts monitored
- ✓ Anomaly detection for unusual patterns
- ✓ Incident response plan documented
- ✓ Regular security audits scheduled

## The Road Ahead: Staying Secure in an Evolving Landscape

Security isn't a destination — it's a journey. As MCP evolves and new attack vectors emerge, your security posture must adapt. The emergence of AI-specific attacks like prompt injection and tool poisoning means traditional security measures alone aren't enough.

Stay informed by following security advisories from the MCP community, participating in security-focused discussions, and regularly updating your dependencies. Consider joining bug bounty programs to have ethical hackers test your implementations.

Remember, the goal isn't to build an impenetrable fortress (that's impossible) but to make your MCP server a harder target than the alternatives. By implementing the security measures outlined in this guide, you're already ahead of 90% of deployments.

## Server wrap up.

We've transformed your MCP server from an open door to a secure vault, implementing industry-standard security practices tailored for AI integrations. By combining OAuth 2.1 authentication, TLS encryption, comprehensive input validation, and intelligent rate limiting, you've built a foundation that can withstand the threats of production deployment.

Security might seem overwhelming, but it's really about consistent application of proven patterns. Each security layer we've added works together to create defense in depth — if one fails, others stand ready to protect your system.

As you deploy your secure MCP servers, remember that security is everyone's responsibility. Share your experiences, contribute to the community's security knowledge, and help make the entire MCP ecosystem more secure. Together, we can ensure that the AI revolution doesn't become a security nightmare.

Now let’s hook up some clients and hosts to your now remote secure MCP server. 

## Connecting Securely: Integrating Clients with Your Fortified MCP Server

Now that we've built a fortress-like MCP server with OAuth 2.1, TLS encryption, and comprehensive security measures, we need to show how AI clients can actually connect to it. Think of this as teaching authorized visitors how to properly enter your secure facility — they need the right credentials, must follow security protocols, and should understand how to interact safely with your protected resources.

Let's explore how each major AI platform and framework connects to our secured MCP server, ensuring that our security measures don't become barriers to legitimate use.

## Understanding Secure Client Connections

Before diving into specific implementations, it's crucial to understand what makes a client connection secure. When connecting to our fortified MCP server, every client must:

1. **Obtain valid OAuth 2.1 tokens** through the proper authorization flow
2. **Include authentication headers** with every request
3. **Verify TLS certificates** to prevent man-in-the-middle attacks
4. **Handle token refresh** when access tokens expire
5. **Respect rate limits** and handle 429 responses gracefully

Think of this process like entering a high-security building. You need an access badge (OAuth token), must show it at every checkpoint (include headers), verify you're in the right building (TLS verification), renew your badge when it expires (token refresh), and respect capacity limits (rate limiting).

## Claude Desktop: Configuring Secure Connections

Claude Desktop requires special configuration to work with OAuth-secured MCP servers. Unlike simple localhost connections, we need to provide authentication details and ensure secure communication.

Here's how to configure Claude Desktop for our secure MCP server:

```json
{
  "mcpServers": {
    "secure-customer-service": {
      "command": "node",
      "args": ["/path/to/mcp-oauth-client.js"],
      "env": {
        "MCP_SERVER_URL": "https://mcp.example.com",
        "OAUTH_CLIENT_ID": "claude-desktop-client",
        "OAUTH_CLIENT_SECRET": "${SECURE_STORE:oauth_client_secret}",
        "OAUTH_TOKEN_URL": "https://auth.example.com/token",
        "OAUTH_SCOPES": "customer:read ticket:create account:calculate",
        "TLS_VERIFY": "true",
        "TLS_CA_CERT": "/path/to/ca-cert.pem"
      }
    }
  }
}

```

Notice how we're not directly connecting to our Python MCP server. Instead, we're using an OAuth-capable client wrapper that handles the authentication flow. Here's what that wrapper looks like:

```jsx
// mcp-oauth-client.js - OAuth wrapper for Claude Desktop
const { MCPClient } = require('@modelcontextprotocol/sdk');
const axios = require('axios');
const https = require('https');
const fs = require('fs');

class SecureMCPClient {
  constructor() {
    this.serverUrl = process.env.MCP_SERVER_URL;
    this.tokenUrl = process.env.OAUTH_TOKEN_URL;
    this.clientId = process.env.OAUTH_CLIENT_ID;
    this.clientSecret = process.env.OAUTH_CLIENT_SECRET;
    this.scopes = process.env.OAUTH_SCOPES;

    // Configure TLS verification
    if (process.env.TLS_CA_CERT) {
      this.httpsAgent = new https.Agent({
        ca: fs.readFileSync(process.env.TLS_CA_CERT)
      });
    }
  }

  async getAccessToken() {
    try {
      // Use client credentials flow for server-to-server auth
      const response = await axios.post(this.tokenUrl, {
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        scope: this.scopes
      }, {
        httpsAgent: this.httpsAgent
      });

      return response.data.access_token;
    } catch (error) {
      console.error('Failed to obtain access token:', error);
      throw error;
    }
  }

  async connectToMCPServer() {
    // Get fresh access token
    const accessToken = await this.getAccessToken();

    // Create MCP client with auth headers
    const client = new MCPClient({
      serverUrl: this.serverUrl,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'X-Client-Version': '1.0.0'
      },
      httpsAgent: this.httpsAgent,
      // Implement token refresh
      onAuthError: async () => {
        const newToken = await this.getAccessToken();
        client.updateHeaders({
          'Authorization': `Bearer ${newToken}`
        });
      }
    });

    return client;
  }
}

// Initialize and run the secure client
async function main() {
  const secureClient = new SecureMCPClient();
  const mcpClient = await secureClient.connectToMCPServer();

  // Pass through to Claude Desktop
  await mcpClient.connect(process.stdin, process.stdout);
}

main().catch(console.error);

```

This wrapper handles all the security complexity, allowing Claude Desktop to interact with your secure MCP server as if it were a simple local connection.

## OpenAI Integration: Native API with OAuth

OpenAI's native chat completion API requires us to handle OAuth authentication and tool registration manually. Here's a complete implementation that connects to our secure MCP server:

```python
"""Secure OpenAI integration with OAuth-protected MCP server."""

import asyncio
import json
import time
from typing import Dict, List, Optional
import httpx
from contextlib import AsyncExitStack

from openai import AsyncOpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import jwt


class SecureOpenAIMCPClient:
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
        self.http_client = httpx.AsyncClient(
            verify=oauth_config.get('ca_cert_path', True),
            timeout=30.0
        )

    async def get_oauth_token(self) -> str:
        """Obtain OAuth access token using client credentials flow."""
        current_time = time.time()

        # Check if we have a valid token
        if self.access_token and current_time < self.token_expires_at - 60:
            return self.access_token

        # Request new token
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

    async def connect_to_secure_mcp_server(self, server_config: dict):
        """Connect to OAuth-protected MCP server."""
        # Get fresh access token
        access_token = await self.get_oauth_token()

        # Create secure MCP connection with authentication
        server_params = StdioServerParameters(
            command=server_config['command'],
            args=server_config['args'],
            env={
                **server_config.get('env', {}),
                'MCP_AUTH_TOKEN': access_token,
                'MCP_SERVER_URL': self.oauth_config['mcp_server_url']
            }
        )

        stdio_transport = await self.exit_stack.enter_async_context(
            stdio_client(server_params)
        )

        read, write = stdio_transport
        session = await self.exit_stack.enter_async_context(
            ClientSession(read, write)
        )

        # Initialize with auth headers
        await session.initialize(
            client_info={
                "name": "secure-openai-client",
                "version": "1.0.0"
            },
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Client-Type": "openai-native"
            }
        )

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

    async def process_secure_query(self, query: str):
        """Process query with security-aware error handling."""
        messages = [{"role": "user", "content": query}]

        try:
            response = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=messages,
                tools=self.available_tools if self.available_tools else None,
                tool_choice="auto"
            )

            # Handle tool calls with security checks
            if response.choices[0].message.tool_calls:
                for tool_call in response.choices[0].message.tool_calls:
                    tool_name = tool_call.function.name

                    # Verify we have required scopes for this tool
                    required_scopes = self._get_required_scopes(tool_name)
                    if not await self._verify_token_scopes(required_scopes):
                        raise PermissionError(
                            f"Insufficient permissions for {tool_name}"
                        )

                    # Execute tool with fresh token
                    access_token = await self.get_oauth_token()
                    session = self.tool_to_session[tool_name]

                    # Update session auth if needed
                    await session.update_auth(
                        headers={"Authorization": f"Bearer {access_token}"}
                    )

                    # Call the tool
                    tool_args = json.loads(tool_call.function.arguments)
                    result = await session.call_mcp_tool(
                        tool_name,
                        arguments=tool_args
                    )

                    # Handle rate limit responses
                    if hasattr(result, 'error') and 'rate_limit' in str(result.error):
                        retry_after = result.metadata.get('retry_after', 60)
                        print(f"Rate limited. Waiting {retry_after} seconds...")
                        await asyncio.sleep(retry_after)
                        # Retry the tool call
                        result = await session.call_mcp_tool(
                            tool_name,
                            arguments=tool_args
                        )

                    # Process result...

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
    oauth_config = {
        'token_url': 'https://auth.example.com/oauth/token',
        'client_id': 'openai-mcp-client',
        'client_secret': os.environ.get('OAUTH_CLIENT_SECRET'),
        'scopes': 'customer:read ticket:create account:calculate',
        'mcp_server_url': 'https://mcp.example.com',
        'ca_cert_path': '/path/to/ca-cert.pem'  # For TLS verification
    }

    server_config = {
        'command': 'python',
        'args': ['secure_mcp_client.py'],
        'env': {
            'PYTHONPATH': '/path/to/mcp/sdk'
        }
    }

    client = SecureOpenAIMCPClient(
        openai_api_key=os.environ.get('OPENAI_API_KEY'),
        oauth_config=oauth_config
    )

    try:
        await client.connect_to_secure_mcp_server(server_config)
        await client.process_secure_query(
            "Look up customer 12345 and check their account status"
        )
    finally:
        await client.exit_stack.aclose()


if __name__ == "__main__":
    asyncio.run(main())

```

This implementation shows how to properly handle OAuth authentication, token refresh, scope verification, and secure communication with our MCP server. Notice how we check scopes before executing tools and handle various security-related errors gracefully.

### Understanding the OpenAI Integration Flow

The provided code for the `SecureOpenAIMCPClient` is a blueprint for a production-grade client. Its key features are:

1. **Real Authentication**: Instead of mocking a JWT, it calls an actual OAuth token endpoint (`get_oauth_token`) to fetch a real access token. This is how a machine-to-machine (M2M) application would securely authenticate.
2. **Tool Discovery and Scopes**: It is designed to discover available tools from the MCP server and map them to the required OAuth scopes (`_get_required_scopes`).
3. **Security-Aware Execution**: It checks if its token has the necessary permissions (`_verify_token_scopes`) *before* attempting to call a tool.
4. **Error Handling**: It includes logic to handle common security-related HTTP errors, such as `401 Unauthorized` (for expired tokens) and `429 Too Many Requests` (for rate limiting).

## Anthropic Native Integration: Built-in Security Support

Anthropic's native API has excellent support for secure tool execution. Here's how to integrate it with our OAuth-protected MCP server:

```python
"""Secure Anthropic integration with OAuth-protected MCP server."""

import asyncio
import json
import os
from typing import Dict, List
from datetime import datetime, timedelta

from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class SecureAnthropicMCPClient:
    def __init__(self, anthropic_api_key: str, oauth_config: dict):
        self.anthropic = Anthropic(api_key=anthropic_api_key)
        self.oauth_config = oauth_config
        self.sessions = []
        self.available_tools = []
        self.tool_to_session = {}
        self.access_token = None
        self.token_expiry = None

        # Security configuration
        self.require_tls = oauth_config.get('require_tls', True)
        self.verify_certificates = oauth_config.get('verify_certificates', True)

    async def obtain_access_token(self) -> str:
        """Obtain OAuth token with proper error handling and caching."""
        # Check if we have a valid cached token
        if self.access_token and self.token_expiry:
            if datetime.utcnow() < self.token_expiry - timedelta(minutes=5):
                return self.access_token

        # Create secure HTTP client
        async with httpx.AsyncClient(
                verify=self.oauth_config.get('ca_cert_path', True)
        ) as client:

            # Prepare OAuth request with PKCE
            code_verifier = self._generate_code_verifier()
            code_challenge = self._generate_code_challenge(code_verifier)

            response = await client.post(
                self.oauth_config['token_url'],
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.oauth_config['client_id'],
                    'client_secret': self.oauth_config['client_secret'],
                    'scope': self.oauth_config['scopes'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256'
                },
                headers={
                    'Accept': 'application/json',
                    'User-Agent': 'AnthropicMCPClient/1.0'
                }
            )

            if response.status_code != 200:
                raise Exception(
                    f"OAuth authentication failed: {response.status_code} - {response.text}"
                )

            token_data = response.json()
            self.access_token = token_data['access_token']

            # Calculate token expiry
            expires_in = token_data.get('expires_in', 3600)
            self.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

            return self.access_token

    def _generate_code_verifier(self) -> str:
        """Generate PKCE code verifier."""
        import secrets
        import base64
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        return verifier

    def _generate_code_challenge(self, verifier: str) -> str:
        """Generate PKCE code challenge from verifier."""
        import hashlib
        import base64
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        return challenge

    async def connect_to_secure_server(self, server_name: str, server_config: dict):
        """Connect to MCP server with comprehensive security checks."""
        try:
            # Get fresh OAuth token
            access_token = await self.obtain_access_token()

            # Create secure connection parameters
            server_params = StdioServerParameters(
                command=server_config['command'],
                args=server_config['args'],
                env={
                    **server_config.get('env', {}),
                    'MCP_OAUTH_TOKEN': access_token,
                    'MCP_TLS_VERIFY': str(self.verify_certificates),
                    'MCP_SERVER_URL': self.oauth_config['mcp_server_url']
                }
            )

            # Establish secure connection
            async with stdio_client(server_params) as (read, write):
                session = ClientSession(read, write)

                # Initialize with security headers
                await session.initialize(
                    client_info={
                        "name": "anthropic-secure-client",
                        "version": "1.0.0"
                    },
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "X-Client-Type": "anthropic-native",
                        "X-Request-ID": self._generate_request_id()
                    }
                )

                self.sessions.append(session)

                # Discover and validate tools
                response = await session.list_tools()

                for tool in response.tools:
                    # Validate tool schema for security
                    if not self._validate_tool_schema(tool):
                        print(f"Warning: Skipping tool {tool.name} due to schema validation failure")
                        continue

                    self.tool_to_session[tool.name] = session

                    # Convert to Anthropic format with security metadata
                    anthropic_tool = {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.inputSchema,
                        "x-security": {
                            "requires_auth": True,
                            "scopes": self._get_tool_scopes(tool.name),
                            "rate_limit": self._get_tool_rate_limit(tool.name)
                        }
                    }
                    self.available_tools.append(anthropic_tool)

                print(f"Connected to {server_name} with {len(self.available_tools)} secure tools")

        except Exception as e:
            print(f"Failed to connect to {server_name}: {e}")
            # Log security event
            self._log_security_event("connection_failed", {
                "server": server_name,
                "error": str(e)
            })
            raise

    def _validate_tool_schema(self, tool) -> bool:
        """Validate tool schema for security vulnerabilities."""
        # Check for dangerous patterns in tool descriptions
        dangerous_patterns = [
            'eval(', 'exec(', '__import__', 'subprocess',
            'os.system', 'shell=True'
        ]

        tool_str = json.dumps({
            'name': tool.name,
            'description': tool.description,
            'schema': tool.inputSchema
        })

        for pattern in dangerous_patterns:
            if pattern in tool_str:
                return False

        return True

    def _get_tool_scopes(self, tool_name: str) -> List[str]:
        """Get required OAuth scopes for a tool."""
        scope_map = {
            'get_customer_info': ['customer:read'],
            'create_support_ticket': ['ticket:create'],
            'calculate_account_value': ['account:calculate', 'customer:read'],
            'update_customer': ['customer:write'],
            'delete_customer': ['customer:delete']
        }
        return scope_map.get(tool_name, [])

    def _get_tool_rate_limit(self, tool_name: str) -> Dict:
        """Get rate limit configuration for a tool."""
        # Tools with higher resource usage get stricter limits
        rate_limits = {
            'calculate_account_value': {
                'requests_per_minute': 30,
                'tokens_per_request': 1000
            },
            'get_customer_info': {
                'requests_per_minute': 60,
                'tokens_per_request': 500
            },
            'create_support_ticket': {
                'requests_per_minute': 20,
                'tokens_per_request': 800
            }
        }
        return rate_limits.get(tool_name, {
            'requests_per_minute': 60,
            'tokens_per_request': 500
        })

    def _generate_request_id(self) -> str:
        """Generate unique request ID for tracing."""
        import uuid
        return str(uuid.uuid4())

    def _log_security_event(self, event_type: str, details: Dict):
        """Log security-relevant events."""
        import logging
        security_logger = logging.getLogger('security')
        security_logger.info(f"Security Event: {event_type}", extra={
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details
        })

    async def process_secure_query(self, query: str):
        """Process query with comprehensive security handling."""
        request_id = self._generate_request_id()

        try:
            messages = [{
                "role": "user",
                "content": query
            }]

            # Create message with security context
            response = self.anthropic.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=2048,
                tools=self.available_tools,
                messages=messages,
                metadata={
                    "request_id": request_id,
                    "security_context": "production"
                }
            )

            # Process response with security checks
            for content in response.content:
                if content.type == "tool_use":
                    # Verify tool permissions
                    required_scopes = self._get_tool_scopes(content.name)
                    if not await self._verify_token_has_scopes(required_scopes):
                        self._log_security_event("insufficient_permissions", {
                            "tool": content.name,
                            "required_scopes": required_scopes,
                            "request_id": request_id
                        })
                        raise PermissionError(
                            f"Insufficient permissions for tool: {content.name}"
                        )

                    # Check rate limits
                    rate_limit = self._get_tool_rate_limit(content.name)
                    if not await self._check_rate_limit(content.name, rate_limit):
                        self._log_security_event("rate_limit_exceeded", {
                            "tool": content.name,
                            "request_id": request_id
                        })
                        raise Exception("Rate limit exceeded")

                    # Execute tool with fresh token
                    access_token = await self.obtain_access_token()
                    session = self.tool_to_session[content.name]

                    # Add security headers for this specific call
                    result = await session.call_mcp_tool(
                        content.name,
                        arguments=content.input,
                        headers={
                            "Authorization": f"Bearer {access_token}",
                            "X-Request-ID": request_id,
                            "X-Tool-Call-ID": content.id
                        }
                    )

                    # Log successful tool execution
                    self._log_security_event("tool_executed", {
                        "tool": content.name,
                        "request_id": request_id,
                        "success": True
                    })

                    # Handle result...

        except Exception as e:
            self._log_security_event("query_failed", {
                "error": str(e),
                "request_id": request_id
            })
            raise

    async def _verify_token_has_scopes(self, required_scopes: List[str]) -> bool:
        """Verify current token has required scopes."""
        # In production, decode and verify JWT token
        # This is a simplified example
        return True  # Implement actual verification

    async def _check_rate_limit(self, tool_name: str, limits: Dict) -> bool:
        """Check if rate limit allows this request."""
        # Implement actual rate limit checking with Redis or similar
        return True  # Simplified for example


# Secure usage example
async def main():
    oauth_config = {
        'token_url': 'https://auth.example.com/oauth/token',
        'client_id': 'anthropic-secure-client',
        'client_secret': os.environ.get('ANTHROPIC_OAUTH_SECRET'),
        'scopes': 'customer:read ticket:create account:calculate',
        'mcp_server_url': 'https://mcp.example.com',
        'ca_cert_path': '/path/to/ca-cert.pem',
        'require_tls': True,
        'verify_certificates': True
    }

    client = SecureAnthropicMCPClient(
        anthropic_api_key=os.environ.get('ANTHROPIC_API_KEY'),
        oauth_config=oauth_config
    )

    await client.connect_to_secure_server(
        "secure-customer-service",
        {
            'command': 'python',
            'args': ['secure_mcp_wrapper.py'],
            'env': {'PYTHONPATH': '/path/to/mcp'}
        }
    )

    await client.process_secure_query(
        "Look up customer 12345 and create a high-priority support ticket"
    )


if __name__ == "__main__":
    asyncio.run(main())

```

## LangChain: Enterprise-Ready Security Integration

LangChain's flexibility makes it perfect for enterprise environments where security is paramount. Here's how to integrate LangChain with our secure MCP server:

```python
"""Secure LangChain integration with OAuth-protected MCP server."""

import asyncio
import os
from typing import Dict, List, Optional
from datetime import datetime

from langchain_mcp_adapters.client import SecureMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor
from langchain.memory import ConversationSummaryBufferMemory
from langchain.callbacks import CallbackManager
from langchain.callbacks.tracers import LangChainTracer
from langgraph.prebuilt import create_react_agent
import httpx

class SecurityAwareMCPClient(SecureMCPClient):
    """Extended MCP client with comprehensive security features."""

    def __init__(self, servers_config: Dict, oauth_config: Dict):
        # Initialize with OAuth configuration
        self.oauth_config = oauth_config
        self.access_tokens = {}
        self.token_expiries = {}

        # Security monitoring
        self.security_events = []
        self.failed_auth_attempts = {}

        # Initialize parent with modified config
        secure_servers_config = self._add_security_to_servers(servers_config)
        super().__init__(secure_servers_config)

    def _add_security_to_servers(self, servers_config: Dict) -> Dict:
        """Add security configuration to each server."""
        secure_config = {}

        for server_name, config in servers_config.items():
            secure_config[server_name] = {
                **config,
                'env': {
                    **config.get('env', {}),
                    'OAUTH_CLIENT_ID': self.oauth_config['client_id'],
                    'OAUTH_CLIENT_SECRET': self.oauth_config['client_secret'],
                    'OAUTH_TOKEN_URL': self.oauth_config['token_url'],
                    'TLS_VERIFY': 'true',
                    'SECURITY_MONITORING': 'true'
                },
                'security': {
                    'require_auth': True,
                    'validate_schemas': True,
                    'log_all_calls': True
                }
            }

        return secure_config

    async def get_tools_with_security(self) -> List:
        """Get tools with security wrappers."""
        # Get base tools
        tools = await self.get_tools()

        # Wrap each tool with security checks
        secure_tools = []
        for tool in tools:
            secure_tool = self._create_secure_tool_wrapper(tool)
            secure_tools.append(secure_tool)

        return secure_tools

    def _create_secure_tool_wrapper(self, tool):
        """Create a security-aware wrapper for MCP tools."""
        original_func = tool.func

        async def secure_tool_func(**kwargs):
            # Pre-execution security checks
            await self._pre_execution_security_check(tool.name, kwargs)

            # Get fresh token for this execution
            access_token = await self._get_access_token_for_tool(tool.name)

            # Add auth headers to the execution context
            execution_context = {
                'headers': {
                    'Authorization': f'Bearer {access_token}',
                    'X-Tool-Name': tool.name,
                    'X-Execution-ID': self._generate_execution_id()
                }
            }

            try:
                # Execute with monitoring
                start_time = datetime.utcnow()
                result = await original_func(**kwargs, _context=execution_context)
                execution_time = (datetime.utcnow() - start_time).total_seconds()

                # Log successful execution
                self._log_tool_execution(tool.name, True, execution_time)

                return result

            except Exception as e:
                # Log failed execution
                self._log_tool_execution(tool.name, False, 0, str(e))

                # Handle specific security errors
                if "401" in str(e) or "unauthorized" in str(e).lower():
                    # Token might be expired, refresh and retry
                    self.access_tokens[tool.name] = None
                    access_token = await self._get_access_token_for_tool(tool.name)
                    execution_context['headers']['Authorization'] = f'Bearer {access_token}'
                    return await original_func(**kwargs, _context=execution_context)

                raise

        # Copy tool attributes
        tool.func = secure_tool_func
        tool.coroutine = secure_tool_func
        tool.description = f"[SECURE] {tool.description}"

        return tool

    async def _pre_execution_security_check(self, tool_name: str, args: Dict):
        """Perform security checks before tool execution."""
        # Input validation
        if not self._validate_tool_inputs(tool_name, args):
            raise ValueError(f"Invalid inputs for tool {tool_name}")

        # Check rate limits
        if not await self._check_tool_rate_limit(tool_name):
            raise Exception(f"Rate limit exceeded for tool {tool_name}")

        # Verify permissions
        if not await self._verify_tool_permissions(tool_name):
            raise PermissionError(f"Insufficient permissions for tool {tool_name}")

    def _validate_tool_inputs(self, tool_name: str, args: Dict) -> bool:
        """Validate tool inputs for security threats."""
        # Check for injection attempts
        dangerous_patterns = [
            r'\$\{', r'`', r'&&', r'||', r';',
            r'eval\(', r'exec\(', r'__import__'
        ]

        args_str = str(args)
        for pattern in dangerous_patterns:
            if pattern in args_str:
                self._log_security_event("input_validation_failed", {
                    "tool": tool_name,
                    "pattern": pattern
                })
                return False

        return True

    async def _get_access_token_for_tool(self, tool_name: str) -> str:
        """Get valid access token for tool execution."""
        # Implementation would include OAuth token management
        # This is simplified for the example
        return "secure_access_token"

    def _generate_execution_id(self) -> str:
        """Generate unique execution ID for tracing."""
        import uuid
        return str(uuid.uuid4())

    def _log_tool_execution(self, tool_name: str, success: bool,
                           execution_time: float, error: str = None):
        """Log tool execution for security monitoring."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "success": success,
            "execution_time": execution_time,
            "error": error
        }
        self.security_events.append(event)

    def _log_security_event(self, event_type: str, details: Dict):
        """Log security-relevant events."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "details": details
        }
        self.security_events.append(event)

async def create_secure_langchain_agent():
    """Create a LangChain agent with comprehensive security."""

    # OAuth configuration
    oauth_config = {
        'client_id': 'langchain-enterprise-client',
        'client_secret': os.environ.get('LANGCHAIN_OAUTH_SECRET'),
        'token_url': 'https://auth.example.com/oauth/token',
        'scopes': 'customer:read ticket:create account:calculate'
    }

    # Server configuration
    servers_config = {
        "secure-customer-service": {
            "command": "python",
            "args": ["secure_mcp_wrapper.py"],
            "transport": "stdio"
        }
    }

    # Create secure MCP client
    mcp_client = SecurityAwareMCPClient(servers_config, oauth_config)

    # Get security-wrapped tools
    tools = await mcp_client.get_tools_with_security()

    # Initialize LLM with security context
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0,
        api_key=os.environ.get("OPENAI_API_KEY"),
        model_kwargs={
            "response_format": {"type": "json_object"},
            "seed": 42  # For reproducibility in security contexts
        }
    )

    # Create memory with security considerations
    memory = ConversationSummaryBufferMemory(
        llm=llm,
        max_token_limit=2000,
        return_messages=True,
        # Don't store sensitive information
        exclude_patterns=["password", "ssn", "credit_card"]
    )

    # Set up callbacks for security monitoring
    callbacks = CallbackManager([
        LangChainTracer(
            project_name="secure-mcp-operations",
            # Additional security logging
            metadata={
                "security_context": "production",
                "compliance": "SOC2"
            }
        )
    ])

    # Create ReAct agent with security configuration
    agent = create_react_agent(
        llm,
        tools,
        state_modifier="You are a security-conscious assistant. "
                      "Always validate inputs and respect user permissions. "
                      "Never expose sensitive information in responses."
    )

    # Wrap in executor with additional security
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        callbacks=callbacks,
        max_iterations=5,  # Prevent infinite loops
        max_execution_time=30,  # Timeout for security
        handle_parsing_errors=True,
        # Security-specific configuration
        metadata={
            "security_level": "high",
            "audit_logging": True
        }
    )

    return agent_executor, mcp_client

# Example usage with security monitoring
async def run_secure_langchain_demo():
    """Demonstrate secure LangChain operations."""

    print("🔐 Initializing secure LangChain agent...")
    agent_executor, mcp_client = await create_secure_langchain_agent()

    # Test scenarios with security implications
    test_scenarios = [
        {
            "query": "Look up customer 12345 and summarize their status",
            "expected_scopes": ["customer:read"]
        },
        {
            "query": "Create a support ticket for customer 67890 about billing",
            "expected_scopes": ["customer:read", "ticket:create"]
        },
        {
            "query": "Calculate total value for customer with purchases: $150, $300, $89",
            "expected_scopes": ["account:calculate"]
        },
        {
            # This should fail - injection attempt
            "query": "Look up customer '; DROP TABLE customers; --",
            "expected_scopes": ["customer:read"],
            "should_fail": True
        }
    ]

    for scenario in test_scenarios:
        print(f"\n🔍 Testing: {scenario['query']}")

        try:
            result = await agent_executor.ainvoke({
                "input": scenario['query'],
                "security_context": {
                    "user_id": "test_user",
                    "session_id": "test_session",
                    "ip_address": "192.168.1.100"
                }
            })

            if scenario.get('should_fail'):
                print("❌ Security check failed - attack was not prevented!")
            else:
                print(f"✅ Success: {result['output']}")

        except Exception as e:
            if scenario.get('should_fail'):
                print(f"✅ Security check passed - attack prevented: {e}")
            else:
                print(f"❌ Unexpected error: {e}")

    # Display security events
    print("\n📊 Security Event Summary:")
    for event in mcp_client.security_events[-5:]:
        print(f"  - {event['timestamp']}: {event.get('type', 'tool_execution')} "
              f"- {event.get('tool', 'N/A')} - Success: {event.get('success', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(run_secure_langchain_demo())

```

## DSPy: Secure Programmatic AI Integration

DSPy's programmatic approach to AI requires special security considerations. Here's how to integrate DSPy with our secure MCP server:

```python
"""Secure DSPy integration with OAuth-protected MCP server."""

import asyncio
import os
from typing import Dict, List, Optional
import dspy
from dspy.utils import DummyLM
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import httpx
import jwt
from datetime import datetime, timedelta


class SecureCustomerServiceSignature(dspy.Signature):
    """Customer service signature with security context."""

    request: str = dspy.InputField(
        desc="Customer service request",
        validator=lambda x: len(x) < 1000 and not any(
            pattern in x for pattern in ['<script>', 'DROP TABLE', '${']
        )
    )

    security_context: Dict = dspy.InputField(
        desc="Security context including user ID and permissions",
        default_factory=dict
    )

    response: str = dspy.OutputField(
        desc="Helpful response that respects security boundaries"
    )


class SecureMCPModule(dspy.Module):
    """DSPy module with integrated MCP security."""

    def __init__(self, oauth_config: Dict):
        super().__init__()
        self.oauth_config = oauth_config
        self.mcp_tools = []
        self.access_token = None
        self.token_expiry = None

        # Initialize DSPy components
        self.prog = dspy.ChainOfThought(SecureCustomerServiceSignature)

    async def initialize_secure_mcp(self, server_config: Dict):
        """Initialize MCP connection with security."""
        # Get OAuth token
        self.access_token = await self._get_oauth_token()

        # Create secure server parameters
        server_params = StdioServerParameters(
            command=server_config['command'],
            args=server_config['args'],
            env={
                **server_config.get('env', {}),
                'OAUTH_TOKEN': self.access_token,
                'SECURITY_MODE': 'strict'
            }
        )

        # Connect and discover tools
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize(
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "X-DSPy-Version": "2.0"
                    }
                )

                # Get available tools
                tools_response = await session.list_tools()

                # Convert to DSPy tools with security wrappers
                for tool in tools_response.tools:
                    dspy_tool = await self._create_secure_dspy_tool(
                        session, tool
                    )
                    self.mcp_tools.append(dspy_tool)

    async def _get_oauth_token(self) -> str:
        """Obtain OAuth token with caching."""
        if self.access_token and self.token_expiry:
            if datetime.utcnow() < self.token_expiry:
                return self.access_token

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.oauth_config['token_url'],
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.oauth_config['client_id'],
                    'client_secret': self.oauth_config['client_secret'],
                    'scope': self.oauth_config['scopes']
                }
            )

            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data['access_token']
                expires_in = token_data.get('expires_in', 3600)
                self.token_expiry = datetime.utcnow() + timedelta(
                    seconds=expires_in - 300  # Refresh 5 min early
                )
                return self.access_token
            else:
                raise Exception(f"OAuth failed: {response.text}")

    async def _create_secure_dspy_tool(self, session, mcp_tool):
        """Create DSPy tool with security wrapper."""

        async def secure_tool_func(**kwargs):
            # Validate inputs
            if not self._validate_tool_inputs(mcp_tool.name, kwargs):
                raise ValueError("Invalid tool inputs detected")

            # Check permissions
            if not await self._check_tool_permissions(mcp_tool.name, kwargs):
                raise PermissionError("Insufficient permissions")

            # Ensure fresh token
            access_token = await self._get_oauth_token()

            # Execute with security context
            result = await session.call_mcp_tool(
                mcp_tool.name,
                arguments=kwargs,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-Tool-Execution-ID": self._generate_execution_id()
                }
            )

            # Sanitize output
            return self._sanitize_tool_output(result)

        # Create DSPy tool
        return dspy.Tool(
            func=secure_tool_func,
            name=f"secure_{mcp_tool.name}",
            desc=f"[SECURE] {mcp_tool.description}"
        )

    def _validate_tool_inputs(self, tool_name: str, inputs: Dict) -> bool:
        """Validate tool inputs for security."""
        # Check for injection patterns
        dangerous_patterns = [
            'eval(', 'exec(', '__import__', 'subprocess',
            'DROP TABLE', 'DELETE FROM', '<script>'
        ]

        input_str = str(inputs).lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in input_str:
                return False

        # Validate specific fields
        if 'customer_id' in inputs:
            if not inputs['customer_id'].isalnum():
                return False

        return True

    async def _check_tool_permissions(self, tool_name: str,
                                      inputs: Dict) -> bool:
        """Check if current token has required permissions."""
        required_scopes = {
            'get_customer_info': ['customer:read'],
            'create_support_ticket': ['ticket:create'],
            'calculate_account_value': ['account:calculate']
        }

        tool_scopes = required_scopes.get(tool_name, [])
        if not tool_scopes:
            return True

        # Decode token to check scopes
        try:
            # In production, verify with public key
            payload = jwt.decode(
                self.access_token,
                options={"verify_signature": False}
            )
            token_scopes = payload.get('scope', '').split()
            return all(scope in token_scopes for scope in tool_scopes)
        except:
            return False

    def _sanitize_tool_output(self, output):
        """Sanitize tool output for security."""
        if hasattr(output, 'content'):
            # Remove any potential sensitive data patterns
            content = str(output.content)

            # Mask potential PII
            import re
            # SSN pattern
            content = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]', content)
            # Credit card pattern
            content = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                             '[CC-REDACTED]', content)

            output.content = content

        return output

    def _generate_execution_id(self) -> str:
        """Generate unique execution ID."""
        import uuid
        return str(uuid.uuid4())

    def forward(self, request: str, security_context: Optional[Dict] = None):
        """Process request with security awareness."""
        # Set up security context
        if not security_context:
            security_context = {
                "user_id": "anonymous",
                "permissions": [],
                "ip_address": "unknown"
            }

        # Create ReAct agent with tools
        react = dspy.ReAct(
            SecureCustomerServiceSignature,
            tools=self.mcp_tools,
            max_iters=5  # Prevent runaway execution
        )

        # Execute with security monitoring
        with self._security_monitor(security_context):
            result = react(
                request=request,
                security_context=security_context
            )

        return result

    def _security_monitor(self, context: Dict):
        """Context manager for security monitoring."""

        class SecurityMonitor:
            def __init__(self, module, context):
                self.module = module
                self.context = context
                self.start_time = None

            def __enter__(self):
                self.start_time = datetime.utcnow()
                # Log execution start
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                duration = (datetime.utcnow() - self.start_time).total_seconds()
                # Log execution end
                if exc_type:
                    # Log security exception
                    pass

        return SecurityMonitor(self, context)


# Secure DSPy usage example
async def run_secure_dspy_demo():
    """Demonstrate secure DSPy operations."""

    # Configure OAuth
    oauth_config = {
        'client_id': 'dspy-secure-client',
        'client_secret': os.environ.get('DSPY_OAUTH_SECRET'),
        'token_url': 'https://auth.example.com/oauth/token',
        'scopes': 'customer:read ticket:create account:calculate'
    }

    # Configure LLM for DSPy
    if os.environ.get('LLM_PROVIDER') == 'openai':
        llm = dspy.LM(
            f"openai/{os.environ.get('OPENAI_MODEL', 'gpt-4')}",
            api_key=os.environ.get('OPENAI_API_KEY')
        )
    else:
        llm = dspy.LM(
            f"anthropic/{os.environ.get('ANTHROPIC_MODEL', 'claude-3')}",
            api_key=os.environ.get('ANTHROPIC_API_KEY')
        )

    dspy.configure(lm=llm)

    # Create secure module
    secure_module = SecureMCPModule(oauth_config)

    # Initialize MCP connection
    await secure_module.initialize_secure_mcp({
        'command': 'python',
        'args': ['secure_mcp_wrapper.py']
    })

    # Test with security context
    test_cases = [
        {
            "request": "Look up customer 12345 and check their status",
            "context": {
                "user_id": "agent_001",
                "permissions": ["customer:read"],
                "ip_address": "10.0.0.1"
            }
        },
        {
            "request": "Create a support ticket for customer 67890",
            "context": {
                "user_id": "agent_002",
                "permissions": ["customer:read", "ticket:create"],
                "ip_address": "10.0.0.2"
            }
        },
        {
            # This should fail - no permissions
            "request": "Delete all customer records",
            "context": {
                "user_id": "malicious_user",
                "permissions": [],
                "ip_address": "192.168.1.666"
            }
        }
    ]

    for test in test_cases:
        print(f"\n🔍 Testing: {test['request']}")
        print(f"   User: {test['context']['user_id']}")
        print(f"   Permissions: {test['context']['permissions']}")

        try:
            result = secure_module.forward(
                request=test['request'],
                security_context=test['context']
            )
            print(f"✅ Result: {result.response}")
        except PermissionError as e:
            print(f"🔒 Permission denied: {e}")
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(run_secure_dspy_demo())

```

## LiteLLM: Universal Security Gateway

LiteLLM's ability to work with multiple LLM providers makes security even more critical. Here's how to implement secure MCP integration with LiteLLM:

```python
"""Secure LiteLLM integration with OAuth-protected MCP server."""

import asyncio
import os
from typing import Dict, List, Optional
import litellm
from litellm import acompletion, Router
from litellm.integrations.custom_logger import CustomLogger
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import json
import httpx
from datetime import datetime
import hashlib


class SecureMCPLogger(CustomLogger):
    """Custom logger for security monitoring."""

    def __init__(self):
        self.security_events = []

    async def async_log_stream_event(self, kwargs, response_obj, start_time, end_time):
        """Log streaming events for security monitoring."""
        pass

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Log successful completions with security context."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "completion_success",
            "model": kwargs.get("model"),
            "user": kwargs.get("user"),
            "duration": (end_time - start_time).total_seconds(),
            "tools_used": self._extract_tool_usage(response_obj)
        }
        self.security_events.append(event)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Log failures for security analysis."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "completion_failure",
            "model": kwargs.get("model"),
            "user": kwargs.get("user"),
            "error": str(response_obj)
        }
        self.security_events.append(event)

    def _extract_tool_usage(self, response):
        """Extract tool usage from response."""
        if hasattr(response, 'choices') and response.choices:
            message = response.choices[0].message
            if hasattr(message, 'tool_calls'):
                return [
                    {"name": tc.function.name, "id": tc.id}
                    for tc in message.tool_calls
                ]
        return []


class SecureLiteLLMMCPClient:
    """LiteLLM client with comprehensive MCP security."""

    def __init__(self, oauth_config: Dict, models_config: List[Dict]):
        self.oauth_config = oauth_config
        self.access_token = None
        self.mcp_tools = []
        self.tool_to_session = {}

        # Initialize security logger
        self.security_logger = SecureMCPLogger()
        litellm.callbacks = [self.security_logger]

        # Configure router for multi-model support with security
        self.router = Router(
            model_list=models_config,
            # Security-focused routing
            routing_strategy="usage-based",  # Route based on token usage
            # Set stricter limits
            max_tokens=2048,
            temperature=0.1,  # Lower temperature for consistency
            # Enable caching with security considerations
            cache=True,
            cache_params={
                "mode": "redis",
                "ttl": 300,  # 5 minute cache
                # Don't cache sensitive operations
                "no_cache_keys": ["password", "secret", "token"]
            }
        )

    async def initialize_secure_mcp(self, server_config: Dict):
        """Initialize MCP connection with security measures."""
        # Get OAuth token
        access_token = await self._get_oauth_token()

        # Create secure wrapper script
        wrapper_config = self._create_secure_wrapper(server_config)

        # Connect to MCP server
        server_params = StdioServerParameters(
            command=wrapper_config['command'],
            args=wrapper_config['args'],
            env={
                **wrapper_config.get('env', {}),
                'OAUTH_TOKEN': access_token,
                'LITELLM_SECURITY': 'enabled'
            }
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize(
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "X-Client": "litellm-secure"
                    }
                )

                # Load tools
                tools_response = await session.list_tools()

                # Convert to OpenAI format with security metadata
                for tool in tools_response.tools:
                    self.tool_to_session[tool.name] = session

                    openai_tool = {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.inputSchema,
                            # Security metadata
                            "x-security": {
                                "requires_auth": True,
                                "rate_limit": self._get_tool_rate_limit(tool.name),
                                "audit": True
                            }
                        }
                    }
                    self.mcp_tools.append(openai_tool)

    def _create_secure_wrapper(self, server_config: Dict) -> Dict:
        """Create secure wrapper configuration."""
        # Generate wrapper script that adds security layers
        wrapper_script = """
import sys
import os
import json
from subprocess import Popen, PIPE

# Security checks
oauth_token = os.environ.get('OAUTH_TOKEN')
if not oauth_token:
    print("Error: No OAuth token provided", file=sys.stderr)
    sys.exit(1)

# Validate token format
if not oauth_token.startswith('Bearer '):
    oauth_token = f'Bearer {oauth_token}'

# Start actual MCP server with security context
env = os.environ.copy()
env['MCP_OAUTH_TOKEN'] = oauth_token
env['MCP_SECURITY_MODE'] = 'strict'

# Run the actual server
proc = Popen(
    {original_command},
    stdin=PIPE,
    stdout=PIPE,
    stderr=PIPE,
    env=env
)

# Pass through stdin/stdout
import select
import fcntl

# Make stdin non-blocking
fcntl.fcntl(sys.stdin, fcntl.F_SETFL, os.O_NONBLOCK)

while proc.poll() is None:
    # Check for input
    readable, _, _ = select.select([sys.stdin, proc.stdout], [], [], 0.1)

    for stream in readable:
        if stream is sys.stdin:
            data = sys.stdin.read()
            if data:
                proc.stdin.write(data.encode())
                proc.stdin.flush()
        elif stream is proc.stdout:
            data = proc.stdout.read()
            if data:
                sys.stdout.buffer.write(data)
                sys.stdout.flush()

# Clean up
proc.wait()
""".replace('{original_command}', json.dumps([
                                                                          server_config['command']] + server_config.get(
            'args', [])
                                             ))

        # Write wrapper script
        import tempfile
        wrapper_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            delete=False
        )
        wrapper_file.write(wrapper_script)
        wrapper_file.close()

        return {
            'command': 'python',
            'args': [wrapper_file.name],
            'env': server_config.get('env', {})
        }

    async def _get_oauth_token(self) -> str:
        """Get OAuth token with security checks."""
        async with httpx.AsyncClient(verify=True) as client:
            response = await client.post(
                self.oauth_config['token_url'],
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.oauth_config['client_id'],
                    'client_secret': self.oauth_config['client_secret'],
                    'scope': self.oauth_config['scopes']
                },
                headers={
                    'User-Agent': 'LiteLLM-Secure/1.0'
                }
            )

            if response.status_code == 200:
                return response.json()['access_token']
            else:
                raise Exception(f"OAuth failed: {response.text}")

    def _get_tool_rate_limit(self, tool_name: str) -> Dict:
        """Get rate limit configuration for tools."""
        # Different limits based on tool resource usage
        limits = {
            'get_customer_info': {
                'requests_per_minute': 100,
                'requests_per_hour': 1000
            },
            'create_support_ticket': {
                'requests_per_minute': 20,
                'requests_per_hour': 200
            },
            'calculate_account_value': {
                'requests_per_minute': 50,
                'requests_per_hour': 500
            }
        }
        return limits.get(tool_name, {
            'requests_per_minute': 60,
            'requests_per_hour': 600
        })

    async def secure_completion(self, messages: List[Dict],
                                user_id: str = None,
                                model: str = None):
        """Perform completion with security measures."""
        # Add security context
        completion_params = {
            "messages": messages,
            "tools": self.mcp_tools,
            "tool_choice": "auto",
            # Security parameters
            "user": user_id or "anonymous",
            "metadata": {
                "security_scan": True,
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        if model:
            completion_params["model"] = model

        # Use router for model selection
        response = await self.router.acompletion(**completion_params)

        # Handle tool calls securely
        if hasattr(response.choices[0].message, 'tool_calls'):
            tool_results = []

            for tool_call in response.choices[0].message.tool_calls:
                # Security validation
                if not await self._validate_tool_call(tool_call, user_id):
                    tool_results.append({
                        "tool_call_id": tool_call.id,
                        "error": "Security validation failed"
                    })
                    continue

                # Execute tool
                result = await self._execute_tool_securely(
                    tool_call,
                    user_id
                )
                tool_results.append(result)

            # Get final response with tool results
            messages.append(response.choices[0].message.model_dump())
            messages.extend(tool_results)

            final_response = await self.router.acompletion(
                messages=messages,
                tools=self.mcp_tools,
                user=user_id
            )

            return final_response

        return response

    async def _validate_tool_call(self, tool_call, user_id: str) -> bool:
        """Validate tool call for security."""
        # Check tool exists
        if not any(t['function']['name'] == tool_call.function.name
                   for t in self.mcp_tools):
            return False

        # Validate arguments
        try:
            args = json.loads(tool_call.function.arguments)

            # Check for injection attempts
            args_str = str(args)
            dangerous_patterns = ['eval(', 'exec(', '__import__', 'DROP TABLE']

            for pattern in dangerous_patterns:
                if pattern in args_str:
                    self._log_security_violation(
                        user_id,
                        f"Injection attempt in tool call: {pattern}"
                    )
                    return False

            return True

        except:
            return False

    async def _execute_tool_securely(self, tool_call, user_id: str) -> Dict:
        """Execute tool with security measures."""
        try:
            # Get fresh token
            access_token = await self._get_oauth_token()

            # Get session for tool
            session = self.tool_to_session[tool_call.function.name]

            # Parse arguments
            args = json.loads(tool_call.function.arguments)

            # Execute with security headers
            result = await session.call_mcp_tool(
                tool_call.function.name,
                arguments=args,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-User-ID": user_id,
                    "X-Tool-Call-ID": tool_call.id
                }
            )

            return {
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": str(result.content)
            }

        except Exception as e:
            self._log_security_violation(
                user_id,
                f"Tool execution failed: {str(e)}"
            )
            return {
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": f"Error: {str(e)}"
            }

    def _log_security_violation(self, user_id: str, details: str):
        """Log security violations."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "security_violation",
            "user": user_id,
            "details": details
        }
        self.security_logger.security_events.append(event)

    def get_security_report(self) -> Dict:
        """Generate security report."""
        events = self.security_logger.security_events

        return {
            "total_events": len(events),
            "violations": [e for e in events if e['type'] == 'security_violation'],
            "failures": [e for e in events if e['type'] == 'completion_failure'],
            "tool_usage": self._analyze_tool_usage(events)
        }

    def _analyze_tool_usage(self, events: List[Dict]) -> Dict:
        """Analyze tool usage patterns."""
        tool_counts = {}

        for event in events:
            if 'tools_used' in event:
                for tool in event['tools_used']:
                    tool_name = tool['name']
                    tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1

        return tool_counts


# Secure usage example
async def run_secure_litellm_demo():
    """Demonstrate secure LiteLLM operations."""

    # OAuth configuration
    oauth_config = {
        'client_id': 'litellm-secure-client',
        'client_secret': os.environ.get('LITELLM_OAUTH_SECRET'),
        'token_url': 'https://auth.example.com/oauth/token',
        'scopes': 'customer:read ticket:create account:calculate'
    }

    # Model configuration with fallbacks
    models_config = [
        {
            "model_name": "gpt-4",
            "litellm_params": {
                "model": "gpt-4",
                "api_key": os.environ.get("OPENAI_API_KEY"),
                "max_tokens": 2048
            }
        },
        {
            "model_name": "claude-3",
            "litellm_params": {
                "model": "claude-3-opus-20240229",
                "api_key": os.environ.get("ANTHROPIC_API_KEY"),
                "max_tokens": 2048
            }
        }
    ]

    # Initialize secure client
    client = SecureLiteLLMMCPClient(oauth_config, models_config)

    # Initialize MCP connection
    await client.initialize_secure_mcp({
        'command': 'python',
        'args': ['secure_mcp_server.py']
    })

    # Test with different security contexts
    test_cases = [
        {
            "messages": [{
                "role": "user",
                "content": "Look up customer 12345 and summarize their account"
            }],
            "user_id": "user_001",
            "model": "gpt-4"
        },
        {
            "messages": [{
                "role": "user",
                "content": "Create a support ticket for customer 67890"
            }],
            "user_id": "user_002",
            "model": "claude-3"
        },
        {
            # Test with potential injection
            "messages": [{
                "role": "user",
                "content": "Look up customer '; DROP TABLE customers; --"
            }],
            "user_id": "malicious_user",
            "model": "gpt-4"
        }
    ]

    for test in test_cases:
        print(f"\n🔍 Testing with {test['model']} for user {test['user_id']}")
        print(f"   Query: {test['messages'][0]['content']}")

        try:
            response = await client.secure_completion(
                messages=test['messages'],
                user_id=test['user_id'],
                model=test['model']
            )

            print(f"✅ Response: {response.choices[0].message.content}")

        except Exception as e:
            print(f"❌ Error: {e}")

    # Generate security report
    print("\n📊 Security Report:")
    report = client.get_security_report()
    print(f"   Total events: {report['total_events']}")
    print(f"   Security violations: {len(report['violations'])}")
    print(f"   Failed requests: {len(report['failures'])}")
    print(f"   Tool usage: {report['tool_usage']}")


if __name__ == "__main__":
    asyncio.run(run_secure_litellm_demo())

```

## Best Practices for Secure Client Implementation

As we've seen through these examples, implementing secure clients requires attention to several critical areas:

**Token Management** is paramount. Never hardcode tokens or secrets in your code. Use environment variables or secure vaults, implement proper token refresh before expiration, and cache tokens appropriately to avoid unnecessary requests.

**Error Handling** must be security-aware. Don't expose internal errors to end users, log security events for monitoring and analysis, implement exponential backoff for rate limits, and handle authentication failures gracefully.

**Input Validation** should happen at every layer. Validate on the client before sending to the server, check for injection patterns and dangerous content, enforce size limits and data types, and use allowlists rather than denylists.

**Monitoring and Auditing** provides your security visibility. Log all tool executions with context, track failed authentication attempts, monitor for unusual patterns, and generate regular security reports.

## Conclusion: Security as a First-Class Citizen

We've transformed the client side of MCP from a potential security liability into a robust, enterprise-ready system. Each client implementation we've explored — from Claude Desktop to LiteLLM — demonstrates that security doesn't have to come at the cost of functionality.

By implementing OAuth 2.1 authentication, validating inputs, monitoring executions, and handling errors gracefully, we've created client implementations that are both powerful and secure. These patterns ensure that your MCP integrations can operate safely in production environments while maintaining the flexibility that makes MCP so valuable.

Remember, security is not a feature you add at the end — it's a fundamental design principle that should guide every decision. As you implement your own MCP clients, use these examples as a foundation, but always consider the unique security requirements of your specific use case.

The combination of a secure MCP server and properly implemented clients creates a system that's ready for the challenges of production deployment. Now go forth and build amazing, secure AI integrations!