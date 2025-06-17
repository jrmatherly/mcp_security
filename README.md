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

## Prerequisites

- Python 3.12.9 (managed via pyenv)
- Poetry for dependency management
- Go Task for build automation
- API key for OpenAI or Anthropic (Claude) OR Ollama installed locally
- Redis server for rate limiting (optional)
- Valid SSL certificates for production deployment

## Setup

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
4. Run the setup task:
    
    ```bash
    task setup
    ```

## Supported LLM Providers

### OpenAI

- Model: gpt-4.1-2025-04-14
- Requires: OpenAI API key

### Anthropic (Claude)

- Model: claude-sonnet-4-20250514
- Requires: Anthropic API key

### Ollama (Local)

- Model: gemma3:27b
- Requires: Ollama installed and gemma3:27b model pulled
- Install: `brew install ollama` (macOS) or see [ollama.ai](https://ollama.ai/)
- Pull model: `ollama pull gemma3:27b`

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
│   │   ├── claude_desktop.py        # Secure Claude Desktop integration
│   │   ├── openai_client.py         # Secure OpenAI client
│   │   ├── anthropic_client.py      # Secure Anthropic client
│   │   ├── langchain_client.py      # Secure LangChain integration
│   │   ├── dspy_client.py           # Secure DSPy integration
│   │   └── litellm_client.py        # Secure LiteLLM integration
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

## Running Examples

Run the secure MCP server:

```bash
task run-server
```

Test individual security components:

```bash
task test-auth           # Test OAuth authentication
task test-validation     # Test input validation
task test-rate-limit     # Test rate limiting
task test-clients        # Test secure client connections
```

Run security demonstrations:

```bash
task demo-security       # Full security demonstration
task demo-attacks        # Demonstrate attack prevention
```

## Available Tasks

- `task setup` - Set up Python environment and install dependencies
- `task run-server` - Run the secure MCP server
- `task run-oauth` - Run the OAuth authorization server
- `task test-security` - Run security tests
- `task demo-security` - Run security demonstrations
- `task format` - Format code with Black and Ruff
- `task clean` - Clean up generated files

## Security Checklist

Before deploying to production, ensure:

**Authentication & Authorization**
- ✓ OAuth 2.1 with PKCE implemented
- ✓ JWT tokens use RS256 or ES256
- ✓ Token expiration set to 15-60 minutes
- ✓ Refresh token rotation implemented
- ✓ Scopes properly defined and enforced

**Transport Security**
- ✓ TLS 1.2 minimum, TLS 1.3 preferred
- ✓ Strong cipher suites configured
- ✓ HSTS header with minimum 1-year max-age
- ✓ Certificate pinning for critical connections

**Input Validation**
- ✓ All inputs validated with Pydantic models
- ✓ Dangerous patterns blocked with regex
- ✓ SQL queries use parameterization exclusively
- ✓ Command execution uses allowlists only

**Rate Limiting & DDoS Protection**
- ✓ Request rate limiting implemented
- ✓ Token-based limits for AI operations
- ✓ Distributed rate limiting with Redis
- ✓ Proper 429 responses with Retry-After

## Example Output

The examples demonstrate:

1. Setting up a production-ready secure MCP server with OAuth 2.1
2. Implementing comprehensive input validation and injection prevention
3. Configuring rate limiting for both requests and AI token usage
4. Connecting various AI clients securely to the protected server
5. Monitoring security events and responding to threats

## Troubleshooting

- **OAuth token errors**: Check your OAuth server configuration and client credentials
- **TLS certificate errors**: Ensure certificates are valid and properly configured
- **Rate limit issues**: Check Redis connection and rate limit configuration
- **Client connection failures**: Verify OAuth tokens and TLS settings

## Learn More

- [FastMCP Documentation](https://gofastmcp.com/)
- [FastMCP Authentication](https://gofastmcp.com/servers/auth/bearer)
- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
