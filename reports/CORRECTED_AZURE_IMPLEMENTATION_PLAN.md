# CORRECTED Azure Implementation Plan - FastMCP OAuth Proxy Required

**MCP Security Project - Azure Entra ID Integration**

*Plan Date: September 8, 2025*
*Based on: FastMCP OAuth Proxy Documentation + Microsoft Azure OAuth 2.1*

## 🚨 CRITICAL CORRECTION

**PREVIOUS PLAN ERROR IDENTIFIED**: Our UPDATED_AZURE_IMPLEMENTATION_PLAN.md recommended AzureProvider as the "FastMCP Native" solution, but **Azure does NOT support Dynamic Client Registration (DCR)**, making AzureProvider incompatible with Azure.

**CORRECT FASTMCP PATTERN**: Azure integration REQUIRES OAuth Proxy pattern due to DCR limitations.

---

## FastMCP Documentation Findings

### ✅ **Confirmed OAuth Proxy Requirement**

From FastMCP documentation: *"OAuth Proxy is specifically designed for traditional OAuth providers that **don't support Dynamic Client Registration (DCR)**"*

**Azure DCR Status**: ❌ **Not Supported** - Requires manual app registration with fixed redirect URIs

**Required Pattern**: OAuth Proxy + JWTVerifier combination for non-DCR providers like Azure

---

## CORRECTED Implementation Strategy

### **Option A: Quick Fix (Immediate) - 2 Hours**

**Purpose**: Resolve OAuth failures with minimal changes  
**Status**: ⚠️ **NOT FastMCP-compliant but functional**

**Changes**:
1. Update client scope format to `"https://graph.microsoft.com/.default"`
2. Configure Azure App Registration with Graph API permissions
3. Keep existing manual OAuth implementation

**Trade-offs**:
- ✅ Quick resolution of current failures
- ❌ Technical debt remains
- ❌ Not following FastMCP patterns

---

### **Option B: OAuth Proxy (FastMCP-Compliant) - 1-2 Days**

**Purpose**: Proper FastMCP-compliant Azure integration  
**Status**: ✅ **CORRECT FastMCP pattern for Azure**

#### **Phase 1: Server Migration to OAuth Proxy**

**Replace Current JWTVerifier with OAuth Proxy Pattern**:

```python
# REMOVE current implementation
- from fastmcp.server.auth.providers.jwt import JWTVerifier
- auth_provider = JWTVerifier(
-     public_key=public_key_pem,  # Local RSA key
-     issuer=Config.get_oauth_issuer_url(),  # Local OAuth server
-     audience=None,
- )

# ADD OAuth Proxy for Azure
+ from fastmcp.server.auth import OAuthProxy
+ from fastmcp.server.auth.providers.jwt import JWTVerifier

+ # JWT verifier for Azure tokens
+ token_verifier = JWTVerifier(
+     jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
+     issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
+     audience=os.environ["AZURE_CLIENT_ID"]
+ )

+ # OAuth Proxy for Azure (non-DCR provider)
+ auth_provider = OAuthProxy(
+     upstream_authorization_endpoint=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
+     upstream_token_endpoint=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
+     upstream_client_id=os.environ["AZURE_CLIENT_ID"],
+     upstream_client_secret=os.environ["AZURE_CLIENT_SECRET"],
+     token_verifier=token_verifier,
+     base_url="http://localhost:8000"
+ )
```

#### **Phase 2: Architecture Simplification**

**MAJOR DISCOVERY**: OAuth Proxy eliminates need for local OAuth server

```bash
# REMOVE - No longer needed with OAuth Proxy
- oauth_server.py (entire local OAuth server)
- task run-oauth (OAuth server startup)
- Local RSA key generation for OAuth

# SIMPLIFIED ARCHITECTURE
- Clients → FastMCP OAuth Proxy → Azure OAuth directly
- No intermediate OAuth server required
```

#### **Phase 3: Environment Configuration**

```bash
# ADD to .env
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret  
AZURE_TENANT_ID=your-azure-tenant-id

# REMOVE - No longer needed
- OAUTH_CLIENT_ID (local OAuth server)
- OAUTH_CLIENT_SECRET (local OAuth server)
- JWT_SECRET_KEY (local signing)
```

#### **Phase 4: Client Configuration Updates**

```python
# UPDATE client OAuth configuration
oauth_config = {
    - "token_url": "http://localhost:8080/token",  # Local OAuth server
    + "mcp_server_url": "http://localhost:8000/mcp",  # FastMCP proxy endpoint
    - "client_id": "openai-mcp-client",  # Local client
    + # OAuth handled by FastMCP proxy - no client credentials needed
    - "scopes": "customer:read ticket:create account:calculate",  # Custom scopes
    + "scopes": "https://graph.microsoft.com/.default",  # Azure Graph scopes
}
```

---

## Azure App Registration Configuration

### **Required Settings for OAuth Proxy**

```yaml
Azure App Registration:
  Authentication:
    - Platform: Web
    - Redirect URIs: 
      - "http://localhost:8000/auth/callback"  # FastMCP proxy callback
      - "https://localhost:8443/auth/callback" # Docker/HTTPS
    - Front-channel logout URL: (optional)
    - Allow public client flows: No
    
  API Permissions:
    - Microsoft Graph:
      - User.Read (Application) - Required for /.default scope
      - User.Read.All (Application) - Optional for enhanced user data
    - Admin consent granted: Yes
    
  Certificates & Secrets:
    - Client secret: Generated and stored in AZURE_CLIENT_SECRET
    
  Token configuration:
    - Optional claims: (customize as needed)
```

### **Scopes and Permissions**

**Standard Microsoft Graph Approach**:
```python
# OAuth Proxy will handle this scope with Azure
scopes = ["https://graph.microsoft.com/.default"]

# Provides access to configured App Registration permissions
# Validated via Azure JWKS at runtime
```

---

## Implementation Comparison

| Aspect | Option A (Quick Fix) | Option B (OAuth Proxy) |
|--------|---------------------|------------------------|
| **FastMCP Compliance** | ❌ Non-compliant | ✅ Fully compliant |
| **Architecture** | Manual OAuth | OAuth Proxy pattern |
| **Local OAuth Server** | ✅ Still required | ❌ Eliminated |
| **Azure Integration** | ⚠️ Workaround | ✅ Proper integration |
| **Token Validation** | Local RSA keys | Azure JWKS |
| **Implementation Time** | 2 hours | 1-2 days |
| **Technical Debt** | High | None |
| **Maintenance** | Complex | Simplified |

---

## Key Architectural Changes

### **Before (Current Architecture)**
```
Client → Local OAuth Server (oauth_server.py) → MCP Server (JWTVerifier) → Tools
          ↑                                      ↑
    Local RSA keys                        Local RSA validation
```

### **After (OAuth Proxy Architecture)**
```
Client → FastMCP OAuth Proxy → Azure OAuth → Tools
                ↑                    ↑
        JWTVerifier (Azure JWKS)    Azure validation
```

**Simplification Benefits**:
- ✅ Eliminates local OAuth server complexity
- ✅ Direct Azure integration
- ✅ FastMCP handles OAuth flow management
- ✅ Azure-native token validation
- ✅ Reduced infrastructure components

---

## Implementation Priorities

### **Immediate (Today)**
- ✅ **Choose implementation approach**: Quick Fix vs OAuth Proxy
- 🔄 **Update Azure App Registration** with correct redirect URIs
- 🔄 **Test OAuth Proxy pattern** in development

### **Short-term (This Week)**  
- 🔄 **Implement chosen approach** systematically
- ⏳ **Remove local OAuth server** (if OAuth Proxy chosen)
- ⏳ **Update all client configurations** 
- ⏳ **Validate end-to-end flow** with Azure

### **Medium-term (Next Sprint)**
- ⏳ **Production deployment** with OAuth Proxy
- ⏳ **Performance optimization** and monitoring
- ⏳ **Documentation updates** and team training

---

## Risk Assessment  

### **Low Risk (OAuth Proxy)**
- Azure App Registration configuration updates
- Environment variable changes
- Client-side configuration updates

### **Medium Risk (OAuth Proxy)**
- Server architecture migration from JWTVerifier to OAuth Proxy
- Removal of local OAuth server infrastructure

### **High Risk**
- None - OAuth Proxy is the recommended FastMCP pattern

---

## Testing Strategy

### **OAuth Proxy Validation**
```bash
# 1. Test FastMCP proxy endpoint
curl http://localhost:8000/auth/authorize
# Should redirect to Azure OAuth

# 2. Test complete OAuth flow
# Start client → Should redirect to Azure → Callback to FastMCP → Success

# 3. Test token validation
# FastMCP should validate tokens via Azure JWKS automatically
```

### **Architecture Testing**
```bash
# Test without local OAuth server (OAuth Proxy only)
task run-server  # Should work without oauth_server.py
task run-openai-client  # Should authenticate via OAuth Proxy
```

---

## Success Criteria

### **Option A (Quick Fix) Complete**
- ✅ Azure OAuth succeeds with Graph API scopes  
- ✅ All clients obtain tokens successfully
- ✅ MCP server validates Azure tokens
- ⚠️ Local OAuth server still required (technical debt)

### **Option B (OAuth Proxy) Complete**
- ✅ FastMCP OAuth Proxy handles Azure authentication
- ✅ No local OAuth server required
- ✅ Azure JWKS validation working
- ✅ All clients authenticate via proxy
- ✅ Simplified architecture with reduced components

---

## Recommended Next Steps

1. **Decision**: Choose Quick Fix (temporary) vs OAuth Proxy (proper solution)
2. **Azure Configuration**: Update App Registration for chosen approach
3. **Implementation**: Execute server and client changes systematically
4. **Validation**: Test complete authentication flow
5. **Cleanup**: Remove unnecessary components (oauth_server.py if OAuth Proxy)

---

**Status**: ✅ **FastMCP OAuth Proxy Pattern Documented - Ready for Implementation**

**Strong Recommendation**: Implement **Option B (OAuth Proxy)** for proper FastMCP-compliant Azure integration and architectural simplification.