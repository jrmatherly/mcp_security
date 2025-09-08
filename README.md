# MCP Security: From Vulnerable to Fortified

This project contains working examples for building secure HTTP-based AI integrations using the Model Context Protocol (MCP) with comprehensive security measures.

## Overview

Learn how to secure your MCP integrations with enterprise-grade security:

- Implement OAuth 2.1 with PKCE authentication
- Configure TLS encryption and security headers
- Add comprehensive input validation and sanitization
- Implement rate limiting and DDoS protection
- Monitor security events and handle incidents
- Connect clients securely to protected MCP servers

## Quick Start

**For Development (no TLS)**:
```bash
task setup && task generate-keys
task run-oauth    # Terminal 1
task run-server   # Terminal 2
```

**For Production (with TLS)**:
```bash
task setup && task generate-keys && task generate-certs
task docker-up
```

## Prerequisites

### Development Setup
- Python 3.12.11 (managed via pyenv)
- Poetry for dependency management
- Go Task for build automation
- API key for OpenAI or Anthropic (Claude) OR Ollama installed locally
- Redis server for rate limiting (optional)

### Docker/Production Setup
- Docker and Docker Compose
- Valid SSL certificates for production deployment
- API key for OpenAI or Anthropic (Claude) OR Ollama installed locally

## Setup

### Development Setup (Local Python)

1. Clone this repository
2. Copy `.env.example` to `.env` and configure your environment:
    
    ```bash
    cp .env.example .env
    ```
    
3. Edit `.env` to configure security and LLM provider:
    - Set your OAuth configuration
    - Add your API keys
    - Configure Redis URL if using distributed rate limiting
    - Set TLS certificate paths
4. Run the setup tasks:
    
    ```bash
    task setup           # Install Python dependencies
    task generate-keys   # Generate RSA keys for JWT
    task generate-certs  # Generate self-signed certificates
    ```

### Docker Setup (Production)

1. Clone this repository
2. Copy `.env.example` to `.env` and configure for Docker:
    
    ```bash
    cp .env.example .env
    ```
    
3. Edit `.env` to configure your production environment:
    - Set your API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY)
    - Configure custom OpenAI endpoint (OPENAI_BASE_URL) if needed
    - Configure JWT secrets and OAuth credentials
    - Set Redis password and other production settings
4. Run the Docker setup:
    
    ```bash
    task generate-keys   # Generate RSA keys for JWT
    task generate-certs  # Generate self-signed certificates
    task docker-build    # Build Docker images
    task docker-up       # Start all services with TLS
    ```

## Technology Stack

**Current Versions (Post-Deprecation Remediation - September 2024)**:

### Core Framework
- **Python**: 3.12.11 (managed via pyenv)
- **FastMCP**: 2.12.2 (Latest MCP server framework with JWTVerifier authentication)
- **MCP SDK**: 1.13.1 (Latest Model Context Protocol SDK)
- **uvicorn**: 0.35.0 (Latest ASGI server with WebSocketsSansIOProtocol support)
- **FastAPI**: 0.115.13+ (High-performance web framework)

### Security & Authentication
- **Authentication**: JWTVerifier (migrated from deprecated BearerAuthProvider)
- **OAuth**: 2.1 with PKCE flow
- **Encryption**: RS256 JWT signatures, TLS 1.3
- **Input Validation**: Pydantic 2.11.5+ with custom security validators
- **Rate Limiting**: Redis-based with configurable thresholds

### AI Platform Support
- **OpenAI**: 1.86.0+ (with agents support)
- **Anthropic**: 0.54.0+ (Claude integration)
- **LangChain**: 0.3.0+ with MCP adapters
- **DSPy**: 2.6.27+ (structured prompting)
- **LiteLLM**: 1.72.4+ (multi-provider proxy)

### Development & Deployment
- **Task Runner**: Go Task (Taskfile.yml)
- **Dependency Management**: Poetry with uv virtual environments
- **Code Quality**: Black, Ruff, pytest with asyncio
- **Containerization**: Docker with nginx TLS termination
- **Database**: Redis 5.0.0+ (rate limiting and caching)

## Supported LLM Providers

### OpenAI
- **Model**: gpt-4.1-2025-04-14
- **Client**: `src/secure_clients/openai_client.py`
- **Task**: `task run-openai-client`
- **Requires**: OpenAI API key (`OPENAI_API_KEY` in .env)
- **Custom Endpoint**: Optional `OPENAI_BASE_URL` for OpenAI-compatible APIs
- **Features**: Function calling with tool results display

### Anthropic (Claude)
- **Model**: claude-sonnet-4-20250514
- **Client**: `src/secure_clients/anthropic_client.py`
- **Task**: `task run-anthropic-client`
- **Requires**: Anthropic API key (`ANTHROPIC_API_KEY` in .env)
- **Features**: Tool execution with Claude's analysis and commentary

### Ollama (Local)
- **Model**: gemma3:27b
- **Requires**: Ollama installed and gemma3:27b model pulled
- **Install**: `brew install ollama` (macOS) or see [ollama.ai](https://ollama.ai/)
- **Pull model**: `ollama pull gemma3:27b`
- **Note**: Server supports Ollama, but no secure client implementation yet

### LangChain (Multi-Provider)
- **Client**: `src/secure_clients/langchain_client.py`
- **Task**: `task run-langchain-client`
- **Requires**: OpenAI API key (uses GPT-4 as the underlying LLM)
- **Custom Endpoint**: Optional `OPENAI_BASE_URL` for OpenAI-compatible APIs
- **Features**: ReAct agent with secure MCP tool integration and OAuth authentication

### DSPy (Multi-Provider)
- **Client**: `src/secure_clients/dspy_client.py`
- **Task**: `task run-dspy-client`
- **Requires**: OpenAI or Anthropic API key (configurable via LLM_PROVIDER)
- **Custom Endpoint**: Optional `OPENAI_BASE_URL` for OpenAI-compatible APIs
- **Features**: DSPy ReAct agent with OAuth 2.1 and TLS security

### LiteLLM (Multi-Provider)
- **Client**: `src/secure_clients/litellm_client.py`
- **Task**: `task run-litellm-client`
- **Requires**: OpenAI or Anthropic API key (configurable via LLM_PROVIDER)
- **Custom Endpoint**: Optional `OPENAI_BASE_URL` for OpenAI-compatible APIs
- **Features**: LiteLLM integration with OAuth 2.1 authentication and JWT signature verification

## Project Structure

```
.
├── src/
│   ├── __init__.py
│   ├── config.py                    # Security and LLM configuration
│   ├── main.py                      # Secure MCP server implementation
│   ├── secure_server.py             # Production-ready secure server
│   ├── oauth_server.py              # OAuth 2.1 authorization server
│   ├── secure_clients/
│   │   ├── __init__.py
│   │   ├── openai_client.py         # ✅ Secure OpenAI GPT-4 client
│   │   ├── anthropic_client.py      # ✅ Secure Anthropic Claude client
│   │   ├── langchain_client.py      # ✅ Secure LangChain integration
│   │   ├── dspy_client.py           # ✅ Secure DSPy integration
│   │   ├── claude_desktop.py        # ⏳ Secure Claude Desktop integration
│   │   └── litellm_client.py        # ✅ Secure LiteLLM integration
│   └── security/
│       ├── __init__.py
│       ├── auth.py                  # Authentication middleware
│       ├── validation.py           # Input validation
│       ├── rate_limiting.py        # Rate limiting implementation
│       └── monitoring.py           # Security monitoring
├── tests/
│   ├── test_security.py            # Security tests
│   └── test_clients.py             # Client integration tests
├── certificates/
│   ├── server.crt                  # TLS certificate
│   └── server.key                  # TLS private key
├── .env.example                    # Environment template
├── Taskfile.yml                    # Task automation
└── pyproject.toml                  # Poetry configuration
```

## Key Security Concepts Demonstrated

1. **OAuth 2.1 with PKCE**: Modern authentication with proof key for code exchange
2. **TLS Encryption**: End-to-end encryption with proper certificate management
3. **Input Validation**: Comprehensive sanitization and injection prevention
4. **Rate Limiting**: Multi-tier rate limiting for requests and AI tokens
5. **Security Monitoring**: Real-time threat detection and incident response
6. **Secure Client Integration**: Protected connections from all major AI platforms

## Running the Application

### Quick Comparison

| Feature | Development Mode | Docker Mode (Production) |
|---------|------------------|-------------------------|
| OAuth URL | http://localhost:8080 | https://localhost:8443 |
| MCP URL | http://localhost:8000 | https://localhost:8001 |
| TLS/HTTPS | ❌ No | ✅ Yes (via nginx) |
| Redis | Local install | Docker container |
| Complexity | Simple | Production-ready |
| Use Case | Development/Testing | Production/Demo |

### Option 1: Development Mode (Without Docker/nginx)

This mode runs services directly with Python, using HTTP without TLS.

#### Environment Variables (.env)
```bash
# Key differences for development mode:
OAUTH_TOKEN_URL=http://localhost:8080/token
MCP_SERVER_URL=http://localhost:8000/mcp
OAUTH_SERVER_HOST=localhost
OAUTH_ISSUER_URL=http://localhost:8080
MCP_SERVER_HOST=localhost
REDIS_URL=redis://localhost:6379
```

#### Running with Tasks
```bash
# Terminal 1: Start OAuth server
task run-oauth           # Runs on http://localhost:8080

# Terminal 2: Start MCP server
task run-server          # Runs on stdio (FastMCP 2.8+)

# Terminal 3: Run AI clients
task run-openai-client     # OpenAI GPT-4 client
task run-anthropic-client  # Anthropic Claude client
task run-langchain-client  # LangChain ReAct agent client
task run-dspy-client       # DSPy ReAct agent client
task run-litellm-client    # LiteLLM multi-provider client
```

#### Running without Tasks
```bash
# Terminal 1: OAuth server
poetry run python src/oauth_server.py

# Terminal 2: MCP server
poetry run python src/main.py

# Terminal 3: AI clients
poetry run python src/secure_clients/openai_client.py     # OpenAI
poetry run python src/secure_clients/anthropic_client.py  # Anthropic
poetry run python src/secure_clients/langchain_client.py  # LangChain
poetry run python src/secure_clients/dspy_client.py       # DSPy
poetry run python src/secure_clients/litellm_client.py    # LiteLLM
```

#### Testing
```bash
# Test OAuth server
curl http://localhost:8080/

# Test with AI clients
task run-openai-client     # Test OpenAI integration
task run-anthropic-client  # Test Anthropic integration
task run-langchain-client  # Test LangChain integration
task run-dspy-client       # Test DSPy integration
task run-litellm-client    # Test LiteLLM integration

# Run all tests
task test
```

### Option 2: Production Mode (With Docker/nginx for TLS)

This mode runs all services in Docker containers with nginx providing TLS termination.

#### Environment Variables (.env)
```bash
# Key differences for Docker mode:
OAUTH_TOKEN_URL=https://localhost:8443/token
MCP_SERVER_URL=https://localhost:8001/mcp
OAUTH_SERVER_HOST=0.0.0.0
OAUTH_ISSUER_URL=https://localhost:8443
MCP_SERVER_HOST=0.0.0.0
REDIS_URL=redis://redis:6379
TLS_CA_CERT_PATH=  # Empty to skip cert verification for self-signed
```

#### Running with Tasks
```bash
# Start all services (nginx, OAuth, MCP, Redis)
task docker-up

# View logs
task docker-logs

# Run AI clients against Docker services
task run-openai-client     # OpenAI client with HTTPS
task run-anthropic-client  # Anthropic client with HTTPS
task run-langchain-client  # LangChain client with HTTPS
task run-dspy-client       # DSPy client with HTTPS
task run-litellm-client    # LiteLLM client with HTTPS

# Stop all services
task docker-down
```

#### Running without Tasks
```bash
# Build and start services
docker-compose build
docker-compose up -d

# View logs
docker-compose logs -f

# Run AI clients with Docker URLs
OAUTH_TOKEN_URL=https://localhost:8443/token \
MCP_SERVER_URL=https://localhost:8001/mcp \
TLS_CA_CERT_PATH= \
poetry run python src/secure_clients/openai_client.py

# Or Anthropic client
OAUTH_TOKEN_URL=https://localhost:8443/token \
MCP_SERVER_URL=https://localhost:8001/mcp \
TLS_CA_CERT_PATH= \
poetry run python src/secure_clients/anthropic_client.py

# Stop services
docker-compose down
```

#### Testing
```bash
# Test OAuth server (via nginx HTTPS)
curl -k https://localhost:8443/

# Test direct container access (from host)
curl http://localhost:8080/  # Direct to OAuth container

# Debug containers
task docker-shell-oauth
task docker-shell-mcp
```

#### Service URLs
- **OAuth Server**: https://localhost:8443 (TLS via nginx)
- **MCP Server**: https://localhost:8001 (TLS via nginx)
- **Direct OAuth**: http://localhost:8080 (container port, not for external use)
- **Direct MCP**: http://localhost:8000 (container port, not for external use)

## Available Tasks

### Core Tasks
- `task setup` - Set up Python environment and install dependencies
- `task generate-keys` - Generate RSA key pair for OAuth JWT signing
- `task generate-certs` - Generate self-signed certificates
- `task test` - Run all pytest tests
- `task format` - Format code with Black and Ruff
- `task clean` - Clean up generated files

### Development Mode Tasks
- `task run-server` - Run MCP server (stdio transport)
- `task run-oauth` - Run OAuth server on port 8080
- `task run-openai-client` - Run OpenAI client (for local services)
- `task run-anthropic-client` - Run Anthropic Claude client (for local services)
- `task run-langchain-client` - Run LangChain ReAct agent client (for local services)
- `task run-dspy-client` - Run DSPy ReAct agent client (for local services)
- `task run-litellm-client` - Run LiteLLM multi-provider client (for local services)

### Docker Mode Tasks
- `task docker-build` - Build Docker images
- `task docker-up` - Start all services with TLS
- `task docker-down` - Stop all services
- `task docker-logs` - View service logs
- `task docker-restart` - Restart services
- `task docker-clean` - Clean up containers and volumes
- `task docker-shell-oauth` - Debug OAuth container
- `task docker-shell-mcp` - Debug MCP container

## Security Checklist

Before deploying to production, ensure:

**Authentication & Authorization**
- ✅ OAuth 2.1 with PKCE implemented
- ✅ JWT tokens use RS256 with JWKS endpoint
- ✅ JWT signature verification in all clients
- ✅ Token expiration set to 15-60 minutes
- ✅ Scopes properly defined and enforced

**Transport Security**
- ✅ TLS 1.2 minimum, TLS 1.3 preferred (via nginx)
- ✅ SSL certificate verification enabled in all clients
- ✅ mkcert certificates for development with proper CA bundle
- ✅ HSTS header with minimum 1-year max-age
- ✅ Certificate chain validation working

**Input Validation**
- ✅ All inputs validated with Pydantic models
- ✅ Dangerous patterns blocked with regex
- ✅ SQL queries use parameterization exclusively
- ✅ Command execution uses allowlists only

**Rate Limiting & DDoS Protection**
- ✅ Request rate limiting implemented
- ✅ Token-based limits for AI operations
- ✅ Distributed rate limiting with Redis
- ✅ Proper 429 responses with Retry-After

## Example Output

The examples demonstrate:

1. Setting up a production-ready secure MCP server with OAuth 2.1
2. Implementing comprehensive input validation and injection prevention
3. Configuring rate limiting for both requests and AI token usage
4. Connecting various AI clients securely to the protected server
5. Monitoring security events and responding to threats

## Troubleshooting

### Development Mode Issues
- **OAuth token errors**: Check your OAuth server configuration and client credentials
- **Import errors**: Run `task setup` to install dependencies
- **Key errors**: Run `task generate-keys` to create RSA key pairs
- **Certificate errors**: Run `task generate-certs` to create self-signed certificates

### Docker Mode Issues
- **TLS certificate errors**: Ensure certificates are valid and properly configured
- **Container startup failures**: Check Docker logs with `task docker-logs`
- **Port conflicts**: Ensure ports 80, 443, 8001, 8080, 8443 are available
- **Redis connection errors**: Check Redis container status and configuration
- **Client connection failures**: Verify OAuth tokens and TLS settings

### Common Solutions
- **Permission denied**: Ensure certificate files have correct permissions (600)
- **Rate limit issues**: Check Redis connection and rate limit configuration
- **API key errors**: Verify your OpenAI/Anthropic API keys in .env file
- **Network issues**: Check Docker network configuration and container connectivity

### Switching Between Modes
When switching between development and Docker modes:
1. **Update .env file**: Change the URLs as shown in the comparison table
2. **Stop all services**: Ensure no port conflicts
3. **For Docker → Development**: Stop Docker (`task docker-down`) before starting local services
4. **For Development → Docker**: Stop local services (Ctrl+C) before starting Docker

## Learn More

- [FastMCP Documentation](https://gofastmcp.com/)
- [FastMCP Authentication](https://gofastmcp.com/servers/auth/bearer)
- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
