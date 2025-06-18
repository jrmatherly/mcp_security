# SSL Certificate Troubleshooting Journey: From "Session Terminated" to Success

## The Problem: MCP Client SSL Certificate Verification Failures

When attempting to connect an OpenAI client to a secure MCP server running behind nginx with TLS termination, we 
encountered the dreaded "Session terminated" error. This document chronicles the debugging journey and the multiple 
issues that needed to be resolved.

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