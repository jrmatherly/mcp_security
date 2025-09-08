# MCP Security: From Vulnerable to Fortified

This project contains working examples for building secure HTTP-based AI integrations using the Model Context Protocol (MCP) with comprehensive security measures.

## Overview

Learn how to secure your MCP integrations with enterprise-grade security:

- **Azure OAuth Proxy**: FastMCP OAuth Proxy with Azure Entra ID authentication
- **Enterprise Integration**: Direct Azure OAuth 2.1 integration with JWKS validation  
- **TLS Encryption**: End-to-end security with configurable certificate management
- **Input Validation**: Comprehensive sanitization and injection prevention
- **Rate Limiting**: Multi-tier protection for requests and AI token usage
- **Security Monitoring**: Real-time threat detection and incident response
- **Multi-Platform Clients**: Secure connections from OpenAI, Anthropic, LangChain, DSPy, and LiteLLM

## Quick Start

**For Development (Azure OAuth Proxy)**:
```bash
task setup
# Configure Azure credentials in .env
task run-server   # Single service with OAuth Proxy
```

**For Production (with TLS)**:
```bash
task setup && task generate-certs
# Configure Azure credentials in .env
task docker-up
```

## Prerequisites

### Development Setup
- Python 3.12.11 (managed via pyenv)
- Poetry for dependency management
- Go Task for build automation
- **Azure App Registration** with configured OAuth credentials
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
    
3. Edit `.env` to configure Azure and LLM provider:
    - **Set Azure credentials**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
    - Add your API keys (OpenAI/Anthropic)
    - Configure Redis URL if using distributed rate limiting
    - Set TLS certificate paths
4. Run the setup tasks:
    
    ```bash
    task setup           # Install Python dependencies  
    task generate-certs  # Generate self-signed certificates
    ```

### Docker Setup (Production)

1. Clone this repository
2. Copy `.env.example` to `.env` and configure for Docker:
    
    ```bash
    cp .env.example .env
    ```
    
3. Edit `.env` to configure your production environment:
    - **Set Azure credentials**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
    - Set your API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY)
    - Configure custom OpenAI endpoint (OPENAI_BASE_URL) if needed
    - Set Redis password and other production settings
4. Run the Docker setup:
    
    ```bash
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
- **Authentication**: OAuth Proxy with Azure Entra ID integration
- **OAuth**: 2.1 flow via FastMCP OAuth Proxy (Azure non-DCR provider)
- **Token Validation**: Azure JWKS endpoint with RS256 JWT signatures
- **Encryption**: TLS 1.3, Azure-managed token signing
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
│   ├── main.py                      # Secure MCP server with OAuth Proxy
│   ├── secure_server.py             # Production-ready secure server
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
| Authentication | Azure OAuth Proxy | Azure OAuth Proxy |
| MCP URL | http://localhost:8000 | https://localhost:8001 |
| TLS/HTTPS | ❌ No | ✅ Yes (via nginx) |
| Redis | Local install | Docker container |
| Architecture | Single service | Production-ready |
| Use Case | Development/Testing | Production/Demo |

### Option 1: Development Mode (Without Docker/nginx)

This mode runs the MCP server directly with Python and Azure OAuth Proxy, using HTTP without TLS.

#### Environment Variables (.env)
```bash
# Key variables for development mode:
# Azure OAuth Proxy Configuration
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret

# Server Configuration
MCP_SERVER_URL=http://localhost:8000/mcp
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000
REDIS_URL=redis://localhost:6379
```

#### Running with Tasks
```bash
# Terminal 1: Start MCP server with OAuth Proxy
task run-server          # Runs on http://localhost:8000 with Azure OAuth Proxy

# Terminal 2: Run AI clients
task run-openai-client     # OpenAI GPT-4 client
task run-anthropic-client  # Anthropic Claude client
task run-langchain-client  # LangChain ReAct agent client
task run-dspy-client       # DSPy ReAct agent client
task run-litellm-client    # LiteLLM multi-provider client
```

#### Running without Tasks
```bash
# Terminal 1: MCP server with OAuth Proxy
poetry run python src/main.py

# Terminal 2: AI clients
poetry run python src/secure_clients/openai_client.py     # OpenAI
poetry run python src/secure_clients/anthropic_client.py  # Anthropic
poetry run python src/secure_clients/langchain_client.py  # LangChain
poetry run python src/secure_clients/dspy_client.py       # DSPy
poetry run python src/secure_clients/litellm_client.py    # LiteLLM
```

#### Testing
```bash
# Test MCP server with OAuth Proxy
curl http://localhost:8000/health

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
# Azure OAuth Proxy Configuration (same as development)
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret

# Docker Server Configuration
MCP_SERVER_URL=https://localhost:8001/mcp
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8000
REDIS_URL=redis://redis:6379
TLS_CA_CERT_PATH=  # Empty to skip cert verification for self-signed
```

#### Running with Tasks
```bash
# Start all services (nginx, MCP with OAuth Proxy, Redis)
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
MCP_SERVER_URL=https://localhost:8001/mcp \
TLS_CA_CERT_PATH= \
poetry run python src/secure_clients/openai_client.py

# Or Anthropic client
MCP_SERVER_URL=https://localhost:8001/mcp \
TLS_CA_CERT_PATH= \
poetry run python src/secure_clients/anthropic_client.py

# Stop services
docker-compose down
```

#### Testing
```bash
# Test MCP server with OAuth Proxy (via nginx HTTPS)
curl -k https://localhost:8001/health

# Test direct container access (from host)
curl http://localhost:8000/health  # Direct to MCP container

# Debug containers
task docker-shell-mcp
```

#### Service URLs
- **MCP Server with OAuth Proxy**: https://localhost:8001 (TLS via nginx)
- **Direct MCP**: http://localhost:8000 (container port, not for external use)

## Available Tasks

### Core Tasks
- `task setup` - Set up Python environment and install dependencies
- `task generate-certs` - Generate self-signed certificates
- `task test` - Run all pytest tests
- `task format` - Format code with Black and Ruff
- `task clean` - Clean up generated files

### Development Mode Tasks
- `task run-server` - Run MCP server with Azure OAuth Proxy (HTTP transport)
- `task run-openai-client` - Run OpenAI client (connects to OAuth Proxy)
- `task run-anthropic-client` - Run Anthropic Claude client (connects to OAuth Proxy)
- `task run-langchain-client` - Run LangChain ReAct agent client (connects to OAuth Proxy)
- `task run-dspy-client` - Run DSPy ReAct agent client (connects to OAuth Proxy)
- `task run-litellm-client` - Run LiteLLM multi-provider client (connects to OAuth Proxy)

### Docker Mode Tasks
- `task docker-build` - Build Docker images
- `task docker-up` - Start all services with TLS
- `task docker-down` - Stop all services
- `task docker-logs` - View service logs
- `task docker-restart` - Restart services
- `task docker-clean` - Clean up containers and volumes
- `task docker-shell-mcp` - Debug MCP container

## Security Checklist

Before deploying to production, ensure:

**Authentication & Authorization**
- ✅ Azure OAuth Proxy with Entra ID integration
- ✅ JWT tokens use RS256 with Azure JWKS endpoint validation
- ✅ FastMCP OAuth Proxy handles token management
- ✅ Azure-managed token expiration and refresh
- ✅ Graph API scopes properly configured

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
- **Azure authentication errors**: Check Azure credentials in .env (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
- **Import errors**: Run `task setup` to install dependencies
- **Certificate errors**: Run `task generate-certs` to create self-signed certificates
- **OAuth Proxy errors**: Verify Azure App Registration configuration and redirect URIs

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
- **Azure authentication failures**: Verify App Registration permissions and admin consent granted

### Switching Between Modes
When switching between development and Docker modes:
1. **Update .env file**: Ensure Azure credentials are configured
2. **Stop all services**: Ensure no port conflicts
3. **For Docker → Development**: Stop Docker (`task docker-down`) before starting local services
4. **For Development → Docker**: Stop local services (Ctrl+C) before starting Docker
5. **Azure Configuration**: Same Azure credentials work for both modes

## Learn More

- [FastMCP Documentation](https://gofastmcp.com/)
- [FastMCP Authentication](https://gofastmcp.com/servers/auth/bearer)
- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
