# Azure App Registration Setup for OAuth Proxy

**Required for Option B Implementation - OAuth Proxy Pattern**

*Created: September 8, 2025*  
*Based on: FastMCP OAuth Proxy + Azure Entra ID Requirements*

---

## Overview

This document provides step-by-step instructions for configuring Azure App Registration to work with the FastMCP OAuth Proxy implementation.

**Key Change**: Redirect URIs now point to **FastMCP OAuth Proxy endpoints** instead of local OAuth server.

---

## Azure Portal Configuration

### Step 1: Create or Update App Registration

1. **Navigate to Azure Portal**
   - Go to [portal.azure.com](https://portal.azure.com)
   - Navigate to **Azure Active Directory** → **App Registrations**

2. **Create New Registration** (or edit existing):
   - **Name**: `MCP Security FastMCP OAuth Proxy`
   - **Supported account types**: `Accounts in this organizational directory only`
   - **Redirect URI**: Leave blank initially (configure below)

### Step 2: Configure Authentication

Navigate to **Authentication** section:

#### **Platform Configuration**
- **Platform Type**: `Web`
- **Redirect URIs** (CRITICAL - Updated for OAuth Proxy):
  ```
  http://localhost:8000/auth/callback
  https://localhost:8443/auth/callback  
  ```
  
#### **Advanced Settings**
- **Allow public client flows**: `No` 
- **Supported account types**: `Single tenant`
- **Front-channel logout URL**: (Optional) `http://localhost:8000/auth/logout`

### Step 3: API Permissions

Navigate to **API permissions** section:

#### **Required Permissions**
- **Microsoft Graph**:
  - `User.Read` (Application) - **Required for /.default scope**
  - `User.Read.All` (Application) - **Optional for enhanced user data**

#### **Admin Consent**
- Click **Grant admin consent for [Tenant]**
- Status should show **✅ Granted for [Tenant]**

### Step 4: Certificates & Secrets

Navigate to **Certificates & secrets** section:

#### **Client Secret**
1. Click **+ New client secret**
2. **Description**: `FastMCP OAuth Proxy Secret`
3. **Expires**: `24 months` (recommended)
4. **Copy the Value** (not the Secret ID!)
5. Store in `.env` file as `AZURE_CLIENT_SECRET`

### Step 5: Token Configuration

Navigate to **Token configuration** section:

#### **Optional Claims** (Customize as needed)
- **ID tokens**: `email`, `preferred_username`
- **Access tokens**: `email`, `preferred_username` 

---

## Environment Variables Configuration

Update your `.env` file with the Azure App Registration details:

```bash
# Azure Configuration (for OAuth Proxy)  
AZURE_TENANT_ID=12345678-1234-1234-1234-123456789012
AZURE_CLIENT_ID=87654321-4321-4321-4321-210987654321
AZURE_CLIENT_SECRET=your-client-secret-value-from-step-4

# Server Configuration
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000
```

### Where to Find These Values

| Environment Variable | Azure Portal Location |
|---------------------|----------------------|
| `AZURE_TENANT_ID` | **Overview** → Directory (tenant) ID |
| `AZURE_CLIENT_ID` | **Overview** → Application (client) ID |  
| `AZURE_CLIENT_SECRET` | **Certificates & secrets** → Client secrets → Value |

---

## OAuth Proxy Architecture

### **Redirect Flow (New)**
```
User/Client → FastMCP OAuth Proxy → Azure OAuth → FastMCP OAuth Proxy → MCP Tools
              (localhost:8000)       (microsoft.com)    (localhost:8000)
```

### **Key Differences from Local OAuth**
- **No Local OAuth Server**: `oauth_server.py` completely removed
- **FastMCP Manages Flow**: OAuth Proxy handles authorization code exchange
- **Azure-Native Validation**: Tokens validated via Azure JWKS, not local RSA keys
- **Simplified Architecture**: Single service instead of MCP + OAuth server

---

## Scopes and Permissions

### **Standard Microsoft Graph Approach**
The OAuth Proxy will request the `https://graph.microsoft.com/.default` scope, which provides access to all **configured App Registration permissions**.

```python
# OAuth Proxy Configuration (automatic)
scopes = ["https://graph.microsoft.com/.default"]

# Provides access to:
# - User.Read (if configured in App Registration)
# - User.Read.All (if configured in App Registration) 
# - Any other permissions granted to the App Registration
```

### **Permission Validation**
- **Design Time**: Configure permissions in Azure App Registration
- **Runtime**: Azure validates tokens with JWKS endpoint
- **MCP Server**: Receives pre-validated Azure tokens via OAuth Proxy

---

## Testing the Configuration

### **Step 1: Verify App Registration**
```bash
# Check App Registration details match .env
echo "Tenant ID: $AZURE_TENANT_ID"
echo "Client ID: $AZURE_CLIENT_ID"  
echo "Secret set: $(if [ -n "$AZURE_CLIENT_SECRET" ]; then echo "✅"; else echo "❌"; fi)"
```

### **Step 2: Test MCP Server Startup**
```bash
# Should show "✅ OAuth Proxy configured for Azure Entra ID"
task run-server
```

### **Step 3: Test Client Connection**
```bash
# Should connect via OAuth Proxy (no local OAuth server needed)
task run-openai-client
```

---

## Troubleshooting

### **Error: Missing Azure configuration**
```
⚠️ Missing Azure configuration. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET
```
**Solution**: Verify all three environment variables are set in `.env`

### **Error: Invalid client credentials**  
**Solution**: 
1. Verify `AZURE_CLIENT_SECRET` matches the **Value** from Azure Portal (not Secret ID)
2. Ensure client secret hasn't expired
3. Check `AZURE_CLIENT_ID` matches **Application (client) ID** from Overview

### **Error: Redirect URI mismatch**
**Solution**: 
1. Verify redirect URIs in Azure App Registration match:
   - `http://localhost:8000/auth/callback`
   - `https://localhost:8443/auth/callback`
2. Ensure **Platform type** is set to `Web`

### **Error: Insufficient permissions**
**Solution**:
1. Verify Microsoft Graph permissions are configured
2. Ensure **admin consent** is granted  
3. Check **User.Read** is present and consented

---

## Security Considerations

### **Client Secret Management**
- ✅ Store in `.env` file (not committed to git)
- ✅ Use expiration periods (24 months max recommended)
- ✅ Rotate secrets before expiration
- ❌ Never hardcode in source code

### **Redirect URI Security**
- ✅ Use specific URIs (not wildcards)
- ✅ Include both HTTP (dev) and HTTPS (prod) variants
- ✅ Validate URIs match OAuth Proxy endpoints exactly
- ❌ Never use `http://localhost:*` wildcards

### **Tenant Isolation**
- ✅ Single tenant configuration for enterprise security
- ✅ Restrict to organizational directory only
- ❌ Avoid multi-tenant unless specifically required

---

## Status

✅ **Configuration Ready**: Azure App Registration setup documented  
✅ **Environment Variables**: Template provided in updated `.env.example`  
✅ **Security Guidelines**: Enterprise-grade recommendations included  

**Next Step**: User must configure actual Azure App Registration and update `.env` with real credentials

---

## Related Documentation

- [FastMCP OAuth Proxy Documentation](https://docs.fastmcp.com/oauth-proxy)
- [Microsoft Graph Permissions Reference](https://docs.microsoft.com/graph/permissions-reference)
- [Azure App Registration Best Practices](https://docs.microsoft.com/azure/active-directory/develop/security-best-practices-for-app-registration)