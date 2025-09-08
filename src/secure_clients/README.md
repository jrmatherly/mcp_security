# Secure MCP Clients

This directory contains secure client implementations that demonstrate how to connect to OAuth-protected MCP servers with enterprise-grade security.

## OpenAI Client

The OpenAI client (`openai_client.py`) shows how to:
- Authenticate with OAuth 2.1 client credentials flow
- Connect OpenAI's chat completions API to a secure MCP backend
- Support custom OpenAI-compatible endpoints via `OPENAI_BASE_URL`
- Handle SSL certificate verification for HTTPS endpoints
- Handle rate limiting and token refresh with automatic retry
- Execute MCP tools with proper security context and scope validation

## Anthropic Client

The Anthropic client (`anthropic_client.py`) provides:
- OAuth 2.1 authentication with Claude API integration
- Secure connection to MCP servers with JWT token validation
- Tool discovery and execution with scope-based access control
- SSL certificate verification and error handling
- Real-time conversation flow with tool result integration

## Deployment Options

### Option 1: Local Development (HTTP)

**Prerequisites:**
1. **Start the OAuth Server**:
   ```bash
   task run-oauth
   ```

2. **Start the MCP Server**:
   ```bash
   task run-server
   ```

3. **Set your OpenAI API Key** in `.env`:
   ```env
   OPENAI_API_KEY=sk-your-actual-api-key-here
   OPENAI_BASE_URL=https://your-custom-endpoint.com/v1  # Optional for custom OpenAI endpoints
   ```

4. **Configure for local HTTP** (uncomment in `.env`):
   ```env
   OAUTH_TOKEN_URL=http://localhost:8080/token
   MCP_SERVER_URL=http://localhost:8000/mcp
   ```

**Run the clients:**
```bash
# OpenAI client
task run-openai-client

# Anthropic client (requires ANTHROPIC_API_KEY)
python src/secure_clients/anthropic_client.py
```

### Option 2: Docker with TLS (HTTPS)

**Prerequisites:**
1. **Start Docker services**:
   ```bash
   docker-compose up -d
   ```

2. **Generate SSL certificates** (for local development):
   ```bash
   # Install mkcert
   brew install mkcert  # macOS
   # or follow: https://github.com/FiloSottile/mkcert#installation
   
   # Generate certificates
   bash ./scripts/generate-local-certs.sh
   ```

3. **Configure for Docker HTTPS** (default in `.env`):
   ```env
   OAUTH_TOKEN_URL=https://localhost:8443/token
   MCP_SERVER_URL=https://localhost:8001/mcp/
   ```

**Run the clients with SSL support:**
```bash
# OpenAI client
bash ./scripts/run-client-with-mkcert.sh

# Anthropic client with SSL
ANTHROPIC_API_KEY=sk-ant-... bash ./scripts/run-client-with-mkcert.sh python src/secure_clients/anthropic_client.py
```

## How It Works

The client will:
1. **Check OAuth server availability** via HTTPS/HTTP
2. **Authenticate** using OAuth 2.1 client credentials flow
3. **Connect to MCP server** with Bearer token authentication
4. **Discover available tools** with security scope validation
5. **Execute test queries** using OpenAI to call secure MCP tools

## Troubleshooting

### Local Development Issues
- **"OAuth server is not running"**: Start with `task run-oauth`
- **"Connection failed"**: Start MCP server with `task run-server`
- **"OPENAI_API_KEY not found"**: Add your API key to `.env`

### Docker/TLS Issues
- **"SSL certificate verify failed"**: Run `bash ./scripts/run-client-with-mkcert.sh`
- **"Session terminated"**: Ensure URLs end with trailing slash (`/mcp/`)
- **"OAuth server not accessible"**: Check Docker services with `docker-compose ps`

### SSL Certificate Setup
- **macOS**: `brew install mkcert && mkcert -install`
- **Linux**: Follow [mkcert installation guide](https://github.com/FiloSottile/mkcert#installation)
- **Debug SSL**: Use `DEBUG_SSL=1 bash ./scripts/run-client-with-mkcert.sh`

### Rate Limiting
The client handles rate limits automatically with exponential backoff and retry logic.

## Architecture

### Local Development (HTTP)
```
OpenAI API → OpenAI Client → OAuth Server → MCP Server
                ↓                ↓              ↓
            Chat Model    Access Token    Secure Tools
          (localhost)   (localhost:8080) (localhost:8000)
```

### Docker Deployment (HTTPS)
```
OpenAI API → OpenAI Client → nginx → OAuth Server → MCP Server
                ↓              ↓         ↓              ↓
            Chat Model    TLS Term.  Access Token  Secure Tools
          (remote API)  (ports 8443)  (oauth:8080)  (mcp:8000)
```

## Security Features

The client demonstrates enterprise-grade security:
- **OAuth 2.1** with client credentials and JWT tokens
- **TLS 1.2/1.3** encryption with certificate verification
- **Rate limiting** with automatic retry and backoff
- **Scope validation** for tool access control
- **Input validation** and security monitoring
- **Token refresh** and expiration handling

## Production Considerations

For production deployments:
- Use certificates from trusted CAs (Let's Encrypt, commercial)
- Implement proper certificate rotation and monitoring  
- Configure Redis for distributed rate limiting
- Set up centralized logging and security monitoring
- Use environment-specific OAuth scopes and permissions