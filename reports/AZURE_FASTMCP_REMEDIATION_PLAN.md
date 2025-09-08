# Azure Entra ID + FastMCP Integration Remediation Plan

**MCP Security Project - Azure Authentication Integration**

*Analysis Date: September 8, 2025*

## Executive Summary

After reviewing comprehensive FastMCP documentation for Azure integration, our current implementation has fundamental architectural mismatches with FastMCP's recommended patterns. This plan provides a systematic remediation approach to properly integrate Azure Entra ID using FastMCP's built-in Azure provider.

## Current Implementation Analysis

### ❌ **Current Approach (Non-Compliant)**

**Current Client Architecture**:
```python
# Manual OAuth implementation in each client
oauth_config = {
    "scopes": "customer:read ticket:create account:calculate",  # ❌ Wrong format
    "token_url": "https://login.microsoftonline.com/.../token", # ❌ Manual handling
}
```

**Problems Identified**:
1. **Manual OAuth Implementation**: Clients handle OAuth flows manually instead of using FastMCP providers
2. **Incorrect Scope Format**: Using custom scopes instead of Azure-standard scopes
3. **Missing FastMCP Patterns**: Not leveraging built-in Azure authentication providers
4. **Inconsistent Architecture**: Each client implements OAuth differently

### ✅ **FastMCP Recommended Approach**

**Server-Side Configuration**:
```python
# Use FastMCP's built-in Azure provider
auth_provider = AzureProvider(
    client_id="your-azure-client-id",
    client_secret="your-azure-client-secret", 
    tenant_id="your-azure-tenant-id",
    base_url="http://localhost:8000",
    required_scopes=["User.Read", "email", "openid", "profile"]  # ✅ Azure-standard scopes
)
```

**Client-Side Configuration**:
```python
# Use FastMCP's OAuth client
oauth = OAuth(
    mcp_url="http://localhost:8000/mcp", 
    scopes=["User.Read", "email", "openid", "profile"]
)
```

## FastMCP Azure Integration Requirements

### 🔧 **Azure Configuration Requirements**

1. **Azure App Registration**:
   - ✅ Single/Multi-tenant app registration
   - ✅ Client ID and Client Secret obtained
   - ✅ Tenant ID is **REQUIRED** (cannot use "common")
   - ❌ Redirect URI must be configured: `http://localhost:8000/auth/callback`

2. **Required Azure Scopes**:
   - `"User.Read"` - Basic user profile information
   - `"email"` - User email address
   - `"openid"` - OpenID Connect identity token  
   - `"profile"` - Additional profile information

3. **Azure App Permissions**:
   - Microsoft Graph API permissions for User.Read
   - Delegated permissions (not Application permissions for this flow)

### 📋 **FastMCP Architecture Patterns**

**Pattern 1: AzureProvider (Recommended)**
```python
# Server-side: Use FastMCP's built-in Azure provider
from fastmcp.server.auth.providers.azure import AzureProvider

auth_provider = AzureProvider(
    client_id=os.environ["AZURE_CLIENT_ID"],
    client_secret=os.environ["AZURE_CLIENT_SECRET"],
    tenant_id=os.environ["AZURE_TENANT_ID"],
    base_url="http://localhost:8000",
    required_scopes=["User.Read", "email", "openid", "profile"]
)

mcp = FastMCP(auth_provider=auth_provider)
```

**Pattern 2: OAuth Proxy (Alternative)**
```python
# For more control over the OAuth flow
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.verifiers.jwt import JWTVerifier

auth_provider = OAuthProxy(
    upstream_authorization_endpoint=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
    upstream_token_endpoint=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    upstream_client_id=client_id,
    upstream_client_secret=client_secret,
    token_verifier=JWTVerifier(
        jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        audience=client_id
    ),
    base_url="http://localhost:8000"
)
```

**Pattern 3: Remote OAuth (Enterprise)**
```python
# For enterprise scenarios with existing Azure AD integration
from fastmcp.server.auth import RemoteAuthProvider

auth_provider = RemoteAuthProvider(
    token_verifier=JWTVerifier(
        jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        audience=client_id
    ),
    authorization_servers=[f"https://login.microsoftonline.com/{tenant_id}"],
    base_url="http://localhost:8000"
)
```

## Remediation Implementation Plan

### Phase 1: Server-Side Migration 🔧

**Priority: HIGH**

**Current State**: Manual JWT verification with custom scopes
**Target State**: FastMCP AzureProvider with standard scopes

**Tasks**:
1. **Replace JWTVerifier with AzureProvider**:
   ```python
   # Remove manual implementation in src/main.py
   - from fastmcp.server.auth.providers.jwt import JWTVerifier
   + from fastmcp.server.auth.providers.azure import AzureProvider
   ```

2. **Update Environment Configuration**:
   ```bash
   # Add to .env
   AZURE_CLIENT_ID=your-azure-client-id
   AZURE_CLIENT_SECRET=your-azure-client-secret
   AZURE_TENANT_ID=your-azure-tenant-id
   ```

3. **Configure Azure Scopes**:
   ```python
   # Update scope configuration
   required_scopes=["User.Read", "email", "openid", "profile"]
   ```

4. **Update Redirect URI in Azure**:
   - Add `http://localhost:8000/auth/callback` to Azure App Registration

### Phase 2: Client-Side Migration 🚀

**Priority: MEDIUM**

**Current State**: Manual OAuth implementation in each client
**Target State**: FastMCP OAuth client usage

**Tasks**:
1. **Replace Manual OAuth with FastMCP Client**:
   ```python
   # Remove manual OAuth implementation
   - Manual token requests and management
   + from fastmcp.client.auth import OAuth
   ```

2. **Update Client Configuration**:
   ```python
   oauth = OAuth(
       mcp_url="http://localhost:8000/mcp",
       scopes=["User.Read", "email", "openid", "profile"]
   )
   ```

3. **Remove Custom Scope Mapping**:
   ```python
   # Remove custom scope validation logic
   - def _get_required_scopes(self, tool_name: str)
   - def _verify_token_scopes(self, required_scopes: List[str])
   ```

### Phase 3: Configuration Standardization 📋

**Priority: LOW**

**Current State**: Mixed configuration patterns
**Target State**: Consistent FastMCP configuration

**Tasks**:
1. **Environment Variable Standardization**:
   ```bash
   # Use FastMCP standard variable names
   FASTMCP_SERVER_AUTH_AZURE_CLIENT_ID=...
   FASTMCP_SERVER_AUTH_AZURE_CLIENT_SECRET=...
   FASTMCP_SERVER_AUTH_AZURE_TENANT_ID=...
   ```

2. **Consider fastmcp.json Configuration**:
   ```json
   {
     "auth": {
       "provider": "azure",
       "client_id": "${AZURE_CLIENT_ID}",
       "tenant_id": "${AZURE_TENANT_ID}",
       "required_scopes": ["User.Read", "email", "openid", "profile"]
     }
   }
   ```

## Implementation Priority Matrix

| Component | Current Issue | FastMCP Solution | Priority | Effort |
|-----------|---------------|------------------|----------|--------|
| **Server Auth** | Manual JWTVerifier | AzureProvider | 🔴 HIGH | 🟡 Medium |
| **Client OAuth** | Manual implementation | OAuth client | 🟡 MEDIUM | 🟢 Low |
| **Scope Format** | Custom scopes | Azure-standard scopes | 🔴 HIGH | 🟢 Low |
| **Token Validation** | Custom validation | Built-in verification | 🟡 MEDIUM | 🟢 Low |
| **Configuration** | Mixed patterns | Standard env vars | 🟢 LOW | 🟢 Low |

## Risk Assessment

### 🟢 **Low Risk Changes**
- Environment variable updates
- Scope format changes
- Client configuration updates

### 🟡 **Medium Risk Changes**
- Server authentication provider replacement
- OAuth flow modifications

### 🔴 **High Risk Changes**
- Complete client OAuth rewrite (if pursuing Phase 2)

## Alternative Approaches

### Option A: FastMCP Native (Recommended)
**Pros**: 
- ✅ Follows FastMCP best practices
- ✅ Built-in Azure integration
- ✅ Automatic token management
- ✅ Standard scope handling

**Cons**:
- ❌ Requires server-side changes
- ❌ Clients need OAuth client integration

### Option B: Minimal Fix (Scope Only)
**Pros**:
- ✅ Minimal changes required
- ✅ Quick implementation

**Cons**:
- ❌ Doesn't follow FastMCP patterns
- ❌ Maintains technical debt
- ❌ Limited Azure feature support

### Option C: OAuth Proxy Pattern
**Pros**:
- ✅ More control over OAuth flow
- ✅ Custom scope mapping possible
- ✅ FastMCP compliant

**Cons**:
- ❌ More complex configuration
- ❌ Additional proxy layer

## Recommended Implementation

### 🎯 **Phase 1: Quick Fix (Immediate)**

For immediate resolution of the scope issue:

1. **Update Azure App Registration**:
   - Add `api://your-client-id/.default` as an exposed API scope
   - Or use standard Microsoft Graph scopes: `"https://graph.microsoft.com/.default"`

2. **Update Client Scope Configuration**:
   ```python
   # Quick fix: Use Azure-compliant scope format
   "scopes": "https://graph.microsoft.com/.default"
   ```

### 🚀 **Phase 2: FastMCP Native (Long-term)**

For full FastMCP compliance:

1. **Implement AzureProvider** in server
2. **Migrate clients** to use FastMCP OAuth client
3. **Standardize configuration** patterns

## Success Criteria

### ✅ **Phase 1 Complete**
- Azure OAuth authentication succeeds
- Clients can obtain tokens
- MCP server accepts Azure tokens

### ✅ **Phase 2 Complete**
- Server uses FastMCP AzureProvider
- Clients use FastMCP OAuth client
- Automatic token refresh works
- Standard Azure scopes implemented

### ✅ **Phase 3 Complete**
- Configuration follows FastMCP standards
- Documentation updated
- All clients use consistent patterns

## Timeline Estimate

- **Phase 1 (Quick Fix)**: 2-4 hours
- **Phase 2 (FastMCP Native)**: 1-2 days
- **Phase 3 (Standardization)**: 4-8 hours

**Total Effort**: 2-3 days for complete FastMCP-compliant Azure integration

---

**Next Steps**: 
1. Decide on implementation approach (Quick Fix vs Full Migration)
2. Update Azure App Registration redirect URI
3. Begin Phase 1 implementation with scope format fixes

**Status**: ✅ **Analysis Complete - Implementation Plan Ready**