# Updated Azure Implementation Plan - Microsoft Documentation Compliant

**MCP Security Project - Azure Entra ID Integration**

*Plan Date: September 8, 2025*
*Based on: Microsoft OAuth 2.1 Documentation + FastMCP Patterns*

## Executive Summary

After validating our remediation plan against Microsoft's official OAuth 2.1 and Azure Enterprise App documentation, this updated plan provides a **Microsoft-compliant** approach to integrating with Azure Entra ID using FastMCP's recommended patterns.

## Microsoft Documentation Validation Results

### ✅ **Confirmed Requirements**

1. **Client Credentials Flow**: Microsoft supports OAuth 2.1 client credentials for server-to-server authentication
2. **Scope Format**: Must use `"https://graph.microsoft.com/.default"` for Microsoft Graph API access
3. **Token Endpoint**: Standard endpoint: `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token`
4. **Tenant-Specific**: Tenant ID is required (cannot use "common")
5. **Application Permissions**: Must configure as Application permissions (not Delegated)

### ❌ **Current Implementation Issues**

1. **Invalid Scope Format**: Using `"customer:read ticket:create account:calculate"` instead of Microsoft-required format
2. **Missing App Registration Scopes**: Custom scopes not registered in Azure App
3. **Architecture Mismatch**: Manual OAuth instead of FastMCP AzureProvider

## Recommended Implementation Strategy

### **Option A: Quick Fix (Immediate Resolution) - 2 Hours**

**Purpose**: Resolve current OAuth failures with minimal changes

**Changes Required**:

1. **Update Client Scope Configuration**:
   ```python
   # Current (broken)
   "scopes": "customer:read ticket:create account:calculate"
   
   # Fixed (Microsoft-compliant)
   "scopes": "https://graph.microsoft.com/.default"
   ```

2. **Azure App Registration Configuration**:
   - Add API permissions: Microsoft Graph → User.Read (Application permission)
   - Grant admin consent for tenant
   - Ensure redirect URI: `http://localhost:8000/auth/callback`

3. **Update Server Scope Mapping**:
   ```python
   # Map internal tool permissions to Graph API capabilities
   def _get_required_scopes(tool_name: str) -> list[str]:
       # All tools require basic Graph access
       return ["https://graph.microsoft.com/.default"]
   ```

**Pros**: 
- ✅ Immediate fix for current OAuth failures
- ✅ Microsoft Graph API integration
- ✅ Minimal code changes

**Cons**:
- ❌ Doesn't follow FastMCP recommended patterns
- ❌ All tools get same broad permissions
- ❌ Technical debt remains

---

### **Option B: FastMCP Native (Recommended) - 1-2 Days**

**Purpose**: Full architectural alignment with FastMCP and Microsoft patterns

**Phase 1: Server Migration**

1. **Replace JWTVerifier with AzureProvider**:
   ```python
   # Remove current implementation
   - from fastmcp.server.auth.providers.jwt import JWTVerifier
   
   # Add FastMCP Azure provider
   + from fastmcp.server.auth.providers.azure import AzureProvider
   
   auth_provider = AzureProvider(
       client_id=os.environ["AZURE_CLIENT_ID"],
       client_secret=os.environ["AZURE_CLIENT_SECRET"],
       tenant_id=os.environ["AZURE_TENANT_ID"],
       base_url="http://localhost:8000",
       required_scopes=["https://graph.microsoft.com/.default"]
   )
   ```

2. **Environment Configuration**:
   ```bash
   # Add to .env
   AZURE_CLIENT_ID=your-azure-client-id
   AZURE_CLIENT_SECRET=your-azure-client-secret
   AZURE_TENANT_ID=your-azure-tenant-id
   ```

**Phase 2: Client Migration**

1. **Replace Manual OAuth with FastMCP Client**:
   ```python
   # Remove manual OAuth implementation
   - Manual token requests and management
   
   # Add FastMCP OAuth client
   + from fastmcp.client.auth import OAuth
   
   oauth = OAuth(
       mcp_url="http://localhost:8000/mcp",
       scopes=["https://graph.microsoft.com/.default"]
   )
   ```

2. **Remove Custom Scope Logic**:
   ```python
   # Remove these functions from all clients
   - def _get_required_scopes(self, tool_name: str)
   - def _verify_token_scopes(self, required_scopes: List[str])
   ```

**Pros**:
- ✅ Follows FastMCP recommended patterns
- ✅ Built-in Azure integration
- ✅ Automatic token management
- ✅ Microsoft-compliant OAuth flow

**Cons**:
- ❌ Requires more implementation time
- ❌ Larger architectural changes

---

## Azure App Registration Configuration

### **Required App Registration Settings**

```yaml
App Registration Configuration:
  Authentication:
    - Redirect URIs: 
      - "http://localhost:8000/auth/callback"
      - "https://localhost:8443/auth/callback" (Docker)
    - Allow public client flows: No
    
  API Permissions:
    - Microsoft Graph:
      - Application.Read.All (Application)
      - User.Read.All (Application)
    - Grant admin consent: Yes
    
  Certificates & Secrets:
    - Client Secret: Generated and stored securely
    
  Expose an API (Optional):
    - Application ID URI: api://your-client-id
    - Scopes: (Only if using custom scopes)
```

### **Microsoft Graph vs Custom API Scopes**

**Microsoft Graph Approach (Recommended)**:
```python
# Use Microsoft's standard scopes
scopes = ["https://graph.microsoft.com/.default"]

# Access user info via Microsoft Graph
GET https://graph.microsoft.com/v1.0/me
```

**Custom API Approach (Alternative)**:
```python
# Register custom scopes in Azure App
scopes = ["api://your-client-id/.default"]

# Your MCP server validates these custom scopes
# More complex but allows granular permissions
```

## Implementation Priorities

### **Immediate (Today)**
- ✅ **Choose implementation approach** (Quick Fix vs FastMCP Native)
- ✅ **Update Azure App Registration** with correct permissions
- 🔄 **Test OAuth flow** with corrected scope format

### **Short-term (This Week)**
- 🔄 **Implement chosen approach**
- ⏳ **Update all client configurations**
- ⏳ **Validate end-to-end OAuth flow**
- ⏳ **Update documentation and tests**

### **Medium-term (Next Sprint)**
- ⏳ **Consider Microsoft Graph API integration** for enhanced user data
- ⏳ **Implement proper permission scopes** if using custom API
- ⏳ **Production deployment considerations**

## Risk Assessment

### **Low Risk Changes**
- Scope format updates
- Environment variable additions
- Azure App Registration configuration changes

### **Medium Risk Changes**
- Server authentication provider replacement
- Client OAuth implementation changes

### **High Risk Changes** 
- Complete architectural migration (if choosing FastMCP Native)

## Testing Strategy

### **OAuth Flow Validation**
```bash
# Test token acquisition
curl -X POST https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token \
  -d "grant_type=client_credentials" \
  -d "client_id={client-id}" \
  -d "client_secret={client-secret}" \
  -d "scope=https://graph.microsoft.com/.default"

# Should return valid access token
```

### **MCP Integration Testing**
```bash
# Test each client with corrected OAuth
task run-openai-client
task run-anthropic-client  
task run-langchain-client
```

### **Microsoft Graph API Testing**
```python
# Validate token can access Microsoft Graph
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
```

## Success Criteria

### **Phase 1 Complete (Quick Fix)**
- ✅ Azure OAuth authentication succeeds with corrected scopes
- ✅ All clients can obtain and use access tokens
- ✅ MCP server accepts and validates Azure tokens
- ✅ No OAuth-related errors in application logs

### **Phase 2 Complete (FastMCP Native)**
- ✅ Server uses FastMCP AzureProvider successfully
- ✅ Clients use FastMCP OAuth client implementation
- ✅ Automatic token refresh works reliably
- ✅ All functionality works with Microsoft Graph integration

## Recommended Next Steps

1. **Decision Point**: Choose Quick Fix vs FastMCP Native approach
2. **Azure Configuration**: Update App Registration with correct permissions
3. **Implementation**: Execute chosen approach systematically
4. **Validation**: Test OAuth flow end-to-end
5. **Documentation**: Update all configuration and setup documentation

---

**Status**: ✅ **Microsoft Documentation Compliant - Implementation Plan Ready**

**Recommendation**: Start with **Option A (Quick Fix)** to resolve immediate issues, then consider **Option B (FastMCP Native)** for long-term architectural improvement.