# Secure MCP Clients

This directory contains secure client implementations that demonstrate how to connect to OAuth-protected MCP servers.

## OpenAI Client

The OpenAI client (`openai_client.py`) shows how to:
- Authenticate with OAuth 2.1 client credentials flow
- Connect OpenAI's chat completions API to a secure MCP backend
- Handle rate limiting and token refresh
- Execute MCP tools with proper security context

### Prerequisites

1. **Start the OAuth Server** (in a separate terminal):
   ```bash
   task run-oauth
   ```

2. **Start the MCP Server** (in another terminal):
   ```bash
   task run-server
   ```

3. **Set your OpenAI API Key** in `.env`:
   ```env
   OPENAI_API_KEY=sk-your-actual-api-key-here
   ```

### Running the Client

Once both servers are running:

```bash
task run-openai-client
```

The client will:
1. Check that the OAuth server is available
2. Get an access token using client credentials
3. Connect to the MCP server with authentication
4. Discover available tools
5. Run test queries using OpenAI to call MCP tools

### Troubleshooting

- **"OAuth server is not running"**: Start the OAuth server first with `task run-oauth`
- **"Connection failed"**: Make sure the MCP server is running with `task run-server`
- **"OPENAI_API_KEY not found"**: Add your API key to the `.env` file
- **Rate limiting**: The client handles rate limits automatically with retry logic

### Architecture

```
OpenAI API → OpenAI Client → OAuth Server → MCP Server
                ↓                ↓              ↓
            Chat Model    Access Token    Secure Tools
```

The client demonstrates a complete secure integration where:
- OpenAI provides the AI capabilities
- OAuth provides authentication and authorization
- MCP provides the tools and data access
- All communication is secured with tokens and scopes