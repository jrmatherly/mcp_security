# FastMCP OAuth Proxy Context - Azure Integration

## Overview
Documentation context loaded from FastMCP for implementing OAuth Proxy routes with Azure integration.

## Azure OAuth Integration Pattern

### Server Configuration
```python
from fastmcp import FastMCP
from fastmcp.auth.providers import AzureProvider

auth_provider = AzureProvider(
    client_id="your-client-id",
    client_secret="your-client-secret", 
    tenant_id="your-tenant-id",
    base_url="http://localhost:8000",
    required_scopes=["User.Read", "email", "openid"]
)

mcp = FastMCP(name="Azure Secured App", auth=auth_provider)
```

### Required Azure App Registration Settings
1. **Client ID**: Application (client) ID from Azure App Registration
2. **Client Secret**: Generated secret in Azure App Registration
3. **Tenant ID**: Directory (tenant) ID - **NOW REQUIRED**
4. **Redirect URIs**: Must include `{base_url}/auth/callback`

### Recommended Scopes
- `User.Read`: Basic user profile information
- `email`: User's email address
- `openid`: OpenID Connect authentication
- `profile`: Additional profile information

## OAuth Proxy Configuration

### Core Parameters
```python
from fastmcp.auth import OAuthProxy
from fastmcp.auth.token import JWTVerifier

auth = OAuthProxy(
    upstream_authorization_endpoint="https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize",
    upstream_token_endpoint="https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token",
    upstream_client_id="your-client-id",
    upstream_client_secret="your-client-secret",
    token_verifier=JWTVerifier(...),
    base_url="https://your-server.com"
)
```

### Key Features
- **PKCE Support**: Proof Key for Code Exchange for enhanced security
- **Dynamic Client Registration**: Flexible client configuration
- **Environment Configuration**: Production-ready environment variable support
- **Provider-Specific Parameters**: Support for Azure-specific OAuth parameters

### Authentication Flow
1. Client requests authentication
2. OAuth Proxy redirects to Azure/Microsoft Entra
3. User authenticates with Microsoft
4. Azure returns authorization code
5. OAuth Proxy exchanges code for tokens
6. Tokens are validated using JWTVerifier
7. Authenticated session established

### Environment Variable Pattern
```bash
# Azure OAuth Configuration
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Server Configuration
MCP_BASE_URL=http://localhost:8000
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000
```

### Integration with Current Project
This documentation supports the MCP Security project's existing Azure OAuth Proxy implementation in:
- `src/main.py`: OAuth Proxy server setup
- `src/config.py`: Azure credential configuration
- `src/secure_clients/`: Client authentication patterns

## Security Considerations
- Tenant ID is now required for Azure integration
- Supports single tenant, multi-tenant, and personal account configurations
- OAuth Proxy pattern bridges Azure's OAuth with MCP authentication
- Comprehensive token validation through JWTVerifier

## Next Steps for Implementation
1. Verify Azure App Registration configuration
2. Update OAuth Proxy routes in `src/main.py`
3. Ensure proper token verification setup
4. Test authentication flow with secure clients
5. Validate scope permissions and user access patterns