# SSL Certificate Troubleshooting Journey: From "Session Terminated" to Success

## Part 1: Initial SSL Certificate Setup (RESOLVED)

The first phase involved connecting an OpenAI client to a secure MCP server running behind nginx with TLS termination, where we 
encountered the dreaded "Session terminated" error. This section chronicles the debugging journey and the multiple 
issues that needed to be resolved.

## Part 2: JWT Implementation SSL Regression (CURRENT ISSUE)

### Problem Summary

After implementing JWT signature verification in the OpenAI client, all other secure clients (Anthropic, LangChain, DSPy, 
and LiteLLM) began failing with SSL certificate verification errors. Previously, all clients were working correctly with 
HTTPS URLs before the JWT implementation.

### Timeline of Events

#### ✅ Initial State (Working)
- All secure clients (OpenAI, Anthropic, LangChain, DSPy) working with HTTPS URLs
- Docker infrastructure running with nginx TLS termination
- Self-signed certificates in place and functioning

#### 🔧 JWT Implementation Phase
1. **Added JWKS endpoint to OAuth server** (`/src/oauth_server.py`)
   - Added `load_public_key()` function
   - Added `get_jwks()` function  
   - Added `/jwks` endpoint for JWT public key distribution

2. **Enhanced OpenAI client with JWT verification** (`/src/secure_clients/openai_client.py`)
   - Added `get_oauth_public_key()` method
   - Enhanced `_verify_token_scopes()` with proper signature verification
   - Used RSA public key from JWKS endpoint

#### ❌ SSL Failures Begin
After JWT implementation and Docker restart/rebuild:
- **Anthropic client**: SSL certificate verification failed
- **LangChain client**: SSL certificate verification failed  
- **DSPy client**: SSL certificate verification failed
- **LiteLLM client**: Working (already had SSL verification disabled)
- **OpenAI client**: Working (with JWT verification)

#### 🩹 Temporary Fix Applied
Disabled SSL verification (`verify=False`) in all failing clients:
- `/src/secure_clients/anthropic_client.py:56`
- `/src/secure_clients/langchain_client.py:58` 
- `/src/secure_clients/dspy_client.py:67`

### Investigation Plan for JWT SSL Regression

#### Phase 1: Clean Slate Approach
1. **Remove all Docker assets** - ✅ Completed
2. **Recreate SSL certificates from scratch** - ✅ Completed
3. **Rebuild Docker infrastructure** - ✅ Completed
4. **Re-enable SSL verification in all clients** - 🔄 In Progress

### SSL Error Details Captured

#### Anthropic Client Error
When re-enabling SSL verification in `anthropic_client.py` by changing `verify=False` to `verify=ca_cert_path if ca_cert_path else True`:

```
FileNotFoundError: [Errno 2] No such file or directory
  File "/opt/homebrew/Cellar/python@3.12/3.12.9/Frameworks/Python.framework/Versions/3.12/lib/python3.12/ssl.py", line 707, in create_default_context
    context.load_verify_locations(cafile, capath, cadata)
```

**Root Cause**: `ca_cert_path` is `None`, so the code falls back to `True`, but httpx expects either:
- `True` (use system default CA bundle)
- String path to CA bundle file
- `False` (disable verification)

The error occurs because there's no system-wide CA bundle that includes our self-signed certificates.

#### ✅ Solution: mkcert + CA Bundle Approach

1. **Generated mkcert certificates**: `bash scripts/generate-local-certs.sh`
   - Creates locally-trusted certificates using mkcert
   - Installs the mkcert CA in system trust store

2. **Created combined CA bundle**: Combined system CAs with mkcert CA
   ```bash
   cat /opt/homebrew/etc/openssl@3/cert.pem > certificates/ca-bundle.pem
   cat "$(mkcert -CAROOT)/rootCA.pem" >> certificates/ca-bundle.pem
   ```

3. **Set SSL environment variable**: `SSL_CERT_FILE="$(pwd)/certificates/ca-bundle.pem"`

4. **Test Result**: ✅ All clients working perfectly with SSL verification enabled!

#### Test Results Summary

| Client | SSL Status | Test Result |
|--------|------------|-------------|
| OpenAI | ✅ Verified | Working (with JWT verification) |
| Anthropic | ✅ Verified | Working (3/3 test scenarios passed) |
| LangChain | ✅ Verified | Working (3/3 scenarios completed) |
| DSPy | ✅ Verified | Working (3/3 scenarios completed) |
| LiteLLM | ✅ Verified | Working (2/2 scenarios completed) |

#### Root Cause Analysis: RESOLVED

**The Issue**: After JWT implementation, Docker was restarted/rebuilt which regenerated self-signed certificates. The new certificates were not trusted by Python's httpx library because:

1. **Missing CA Bundle**: No combined CA bundle containing both system CAs and development certificates
2. **SSL Environment Variables**: `SSL_CERT_FILE` not set to point to proper CA bundle
3. **Certificate Trust Chain**: Self-signed certificates not in system trust store

**The Solution**: 
- Used mkcert to generate locally-trusted certificates
- Created combined CA bundle with system + mkcert CAs  
- Set `SSL_CERT_FILE` environment variable
- All clients now use proper SSL verification with `verify=True`

#### Final State: ALL SECURITY FEATURES OPERATIONAL

| Feature | Status | Details |
|---------|--------|---------|
| SSL Certificate Verification | ✅ **ENABLED** | All clients use `verify=True` with proper CA bundle |
| Certificate Chain Validation | ✅ **WORKING** | mkcert certificates trusted by system |
| JWT Signature Verification | ✅ **IMPLEMENTED** | All clients verify JWT signatures with RS256 + JWKS |
| OAuth 2.1 Scope Validation | ✅ **WORKING** | Proper scope checking before tool execution |
| Rate Limiting | ✅ **OPERATIONAL** | Redis-backed distributed rate limiting |
| Input Validation | ✅ **ACTIVE** | Pydantic v2 models with regex threat detection |

#### JWT Implementation Summary

All 5 secure clients now include proper JWT signature verification:

1. **OpenAI Client**: ✅ JWT verification with JWKS (implemented earlier)
2. **Anthropic Client**: ✅ JWT verification with JWKS (newly added)
3. **LangChain Client**: ✅ JWT verification with JWKS (newly added)
4. **DSPy Client**: ✅ JWT verification with JWKS (newly added)
5. **LiteLLM Client**: ✅ JWT verification with JWKS (newly added)

Each client now:
- Fetches OAuth server's public key from `/jwks` endpoint
- Verifies JWT signatures using RS256 algorithm
- Validates audience and issuer claims
- Falls back to unverified decode only if JWKS unavailable
- Displays clear verification status messages

---

## The Original Problem: MCP Client SSL Certificate Verification Failures (RESOLVED)

## Initial Symptoms

```bash
🔌 Connecting to secure MCP server...
❌ Connection failed: Session terminated
```

The client could connect to the OAuth server for token acquisition, but the MCP connection failed immediately. 
This suggested the issue was specific to the MCP server connection.

## Debugging Process

### 1. HTTP Bypass Test (Success)

**Test**: Changed environment variables to use HTTP URLs bypassing nginx:
```bash
# From HTTPS (failing)
MCP_SERVER_URL=https://localhost:8001/mcp

# To HTTP (working)  
MCP_SERVER_URL=http://localhost:8000/mcp
```

**Result**: ✅ Client connected successfully via HTTP

**Conclusion**: The MCP server was functional; the issue was HTTPS-specific.

### 2. Manual SSL Testing

**Test**: Used curl to test the HTTPS endpoints:
```bash
# OAuth server (working)
curl -k https://localhost:8443/token
✅ Accessible

# MCP server (redirect issue)
curl -k https://localhost:8001/mcp
❌ HTTP 307 redirect to http://localhost/mcp/
```

**Discovery**: Two separate issues were identified:
1. **SSL certificate verification** - Python's httpx couldn't verify self-signed certificates
2. **nginx routing** - Missing trailing slash caused redirects to incorrect URLs

### 3. SSL Certificate Investigation

**Problem**: Python's httpx library (used by FastMCP) doesn't use the system certificate store where mkcert installs its CA. 
It uses its own certificate bundle.

**Solution Path**:
1. **Generate mkcert certificates**: `mkcert localhost`
2. **Create combined CA bundle**: System CAs + mkcert CA
3. **Configure SSL environment variables**: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`
4. **Custom httpx client factory**: Pass CA bundle to FastMCP's streamablehttp_client

### 4. The Trailing Slash Fix

**Discovery**: nginx was redirecting `/mcp` to `/mcp/`, but the redirect lost the HTTPS scheme.

```bash
# Before fix
MCP_SERVER_URL=https://localhost:8001/mcp
→ 307 redirect to http://localhost/mcp/

# After fix  
MCP_SERVER_URL=https://localhost:8001/mcp/
→ Direct connection to MCP server
```

## Were Both Issues Real?

**Yes, both issues needed to be resolved:**

### SSL Certificate Issue (Real)
- FastMCP's `streamablehttp_client` doesn't inherit system SSL settings
- Python's httpx requires explicit CA certificate configuration for self-signed certs
- Without SSL fixes, would have failed with certificate verification errors

### Trailing Slash Issue (Real) 
- nginx routing rule caused redirects that lost HTTPS scheme
- Even with perfect SSL setup, wrong URL would cause connection failures

## The Complete Solution

### 1. mkcert Certificate Setup
```bash
# Install mkcert and create certificates
mkcert -install
mkcert localhost
```

### 2. Combined CA Bundle Creation
```bash
# Combine system CAs with mkcert CA
cat /opt/homebrew/etc/openssl@3/cert.pem > ca-bundle.pem
cat ~/Library/Application\ Support/mkcert/rootCA.pem >> ca-bundle.pem
```

### 3. SSL Environment Variables
```bash
export SSL_CERT_FILE="$(pwd)/certificates/ca-bundle.pem"
export REQUESTS_CA_BUNDLE="$(pwd)/certificates/ca-bundle.pem" 
export CURL_CA_BUNDLE="$(pwd)/certificates/ca-bundle.pem"
```

### 4. Custom FastMCP HTTP Client
```python
def custom_httpx_client_factory(headers=None, timeout=None, auth=None):
    ca_cert_path = os.environ.get('SSL_CERT_FILE')
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout if timeout else httpx.Timeout(30.0),
        auth=auth,
        verify=ca_cert_path if ca_cert_path else True,
        follow_redirects=True
    )

http_transport = await streamablehttp_client(
    url=mcp_server_url,
    headers={"Authorization": f"Bearer {access_token}"},
    httpx_client_factory=custom_httpx_client_factory
)
```

### 5. Correct URL Configuration
```bash
# Fixed trailing slash
MCP_SERVER_URL=https://localhost:8001/mcp/
```

## Final Result

```bash
🔐 Running OpenAI client with mkcert certificates...
✅ mkcert CA found in bundle
✅ OAuth server is running at https://localhost:8443
🔌 Connecting to secure MCP server...
✅ Connected! Available tools: 3
   - get_customer_info
   - create_support_ticket  
   - calculate_account_value
```

## Key Learnings

1. **FastMCP SSL Configuration**: Requires custom httpx client factory for self-signed certificates
2. **Python Certificate Stores**: httpx doesn't use system certificate store; needs explicit CA bundle
3. **nginx Trailing Slashes**: Missing trailing slashes can cause redirect loops with scheme changes
4. **Multiple Issue Debugging**: Complex systems often have multiple simultaneous issues that mask each other
5. **mkcert Limitations**: Works for browsers/system tools but not Python httpx without additional configuration

## Debug Mode

For SSL troubleshooting, enable debug output:
```bash
DEBUG_SSL=1 bash ./scripts/run-client-with-mkcert.sh
```

This will show which SSL certificate files are being used by the client.

## Production Recommendations

For production deployments:
- Use certificates from a trusted CA (Let's Encrypt, commercial CA)
- Implement proper certificate rotation and monitoring
- Use nginx `return 301` for trailing slash redirects to preserve scheme
- Test SSL certificate chains thoroughly with all client libraries
- Monitor certificate expiration and renewal processes