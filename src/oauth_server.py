"""
OAuth 2.1 Authorization Server with PKCE support.
Provides secure token generation and validation for MCP clients.
"""

import asyncio
import base64
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Form, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from config import Config

# OAuth server configuration
app = FastAPI(title="OAuth 2.1 Authorization Server", version="1.0.0")
security = HTTPBasic()

# In-memory storage (use proper database in production)
authorization_codes = {}
access_tokens = {}
refresh_tokens = {}
clients = {
    "mcp-secure-client": {
        "client_secret": "secure-client-secret-change-in-production",
        "redirect_uris": ["http://localhost:8080/callback"],
        "scopes": ["customer:read", "ticket:create", "account:calculate", "security:read"]
    },
    "claude-desktop-client": {
        "client_secret": "claude-desktop-secret",
        "redirect_uris": ["http://localhost:3000/callback"],
        "scopes": ["customer:read", "ticket:create", "account:calculate"]
    },
    "openai-mcp-client": {
        "client_secret": "openai-client-secret",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
        "scopes": ["customer:read", "ticket:create", "account:calculate"]
    }
}

# Mock user database
users = {
    "demo_user": {
        "password": "demo_password",
        "scopes": ["customer:read", "ticket:create", "account:calculate", "security:read"]
    },
    "admin_user": {
        "password": "admin_password", 
        "scopes": ["customer:read", "ticket:create", "account:calculate", "security:read", "admin:manage"]
    }
}

class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: Optional[str] = None
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

class AuthorizeRequest(BaseModel):
    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None

def verify_client(client_id: str, client_secret: str = None) -> bool:
    """Verify client credentials."""
    if client_id not in clients:
        return False
    
    if client_secret is not None:
        return clients[client_id]["client_secret"] == client_secret
    
    return True

def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """Verify PKCE code challenge."""
    if method == "S256":
        # Generate code challenge from verifier
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        return challenge == code_challenge
    elif method == "plain":
        return code_verifier == code_challenge
    else:
        return False

def load_private_key():
    """Load RSA private key for JWT signing."""
    private_key_path = Path("keys/private_key.pem")
    
    if not private_key_path.exists():
        raise FileNotFoundError(
            "Private key not found. Run 'python src/generate_keys.py' or 'task generate-keys' first."
        )
    
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    return private_key

def generate_access_token(user_id: str, client_id: str, scopes: List[str]) -> str:
    """Generate JWT access token with RS256 algorithm."""
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "aud": client_id,
        "iss": Config.get_oauth_issuer_url(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "scope": " ".join(scopes),
        "jti": str(uuid.uuid4())
    }
    
    private_key = load_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256")

def generate_refresh_token() -> str:
    """Generate secure refresh token."""
    return secrets.token_urlsafe(32)

@app.get("/")
async def root():
    """OAuth server info endpoint."""
    return {
        "issuer": "mcp-oauth-server",
        "authorization_endpoint": "/authorize",
        "token_endpoint": "/token",
        "supported_grant_types": ["authorization_code", "client_credentials", "refresh_token"],
        "supported_response_types": ["code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": ["customer:read", "ticket:create", "account:calculate", "security:read"]
    }

@app.get("/authorize", response_class=HTMLResponse)
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = "S256"
):
    """OAuth 2.1 authorization endpoint with PKCE."""
    
    # Validate client
    if not verify_client(client_id):
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    # Validate redirect URI
    if redirect_uri not in clients[client_id]["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    # Validate response type
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
    # For demo purposes, return a simple login form
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth 2.1 Authorization</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }}
            .form-group {{ margin: 15px 0; }}
            label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
            input {{ width: 100%; padding: 8px; box-sizing: border-box; }}
            button {{ background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
            .scope {{ background: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }}
        </style>
    </head>
    <body>
        <h2>🔐 MCP OAuth Authorization</h2>
        <p>Application <strong>{client_id}</strong> is requesting access to your account.</p>
        
        <div class="scope">
            <strong>Requested Permissions:</strong><br>
            {scope.replace(' ', '<br>• ').replace(':', ': ')}
        </div>
        
        <form method="post" action="/authorize">
            <input type="hidden" name="response_type" value="{response_type}">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="state" value="{state or ''}">
            <input type="hidden" name="code_challenge" value="{code_challenge or ''}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
            
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="demo_user" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" value="demo_password" required>
            </div>
            
            <button type="submit" name="action" value="approve">Authorize</button>
            <button type="submit" name="action" value="deny">Deny</button>
        </form>
        
        <hr>
        <p><small>Demo users: demo_user/demo_password, admin_user/admin_password</small></p>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@app.post("/authorize")
async def authorize_post(
    response_type: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: str = Form(None),
    code_challenge: str = Form(None),
    code_challenge_method: str = Form("S256"),
    username: str = Form(...),
    password: str = Form(...),
    action: str = Form(...)
):
    """Handle authorization form submission."""
    
    if action == "deny":
        # User denied authorization
        error_uri = f"{redirect_uri}?error=access_denied"
        if state:
            error_uri += f"&state={state}"
        return RedirectResponse(url=error_uri)
    
    # Verify user credentials
    if username not in users or users[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if user has requested scopes
    requested_scopes = scope.split()
    user_scopes = users[username]["scopes"]
    
    if not all(s in user_scopes for s in requested_scopes):
        raise HTTPException(status_code=403, detail="Insufficient user permissions")
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    
    # Store authorization code with metadata
    authorization_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "user_id": username,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 600,  # 10 minutes
        "used": False
    }
    
    # Redirect back to client with authorization code
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"
    
    return RedirectResponse(url=redirect_url)

@app.post("/token")
async def token_endpoint(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(None),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    code_verifier: str = Form(None),
    refresh_token: str = Form(None),
    scope: str = Form(None)
):
    """OAuth 2.1 token endpoint."""
    
    if grant_type == "authorization_code":
        return await handle_authorization_code_grant(
            client_id, client_secret, code, redirect_uri, code_verifier
        )
    elif grant_type == "client_credentials":
        return await handle_client_credentials_grant(client_id, client_secret, scope)
    elif grant_type == "refresh_token":
        return await handle_refresh_token_grant(client_id, client_secret, refresh_token)
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

async def handle_authorization_code_grant(
    client_id: str, client_secret: str, code: str, redirect_uri: str, code_verifier: str
):
    """Handle authorization code grant."""
    
    # Verify client
    if not verify_client(client_id, client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Verify authorization code
    if code not in authorization_codes:
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    
    auth_data = authorization_codes[code]
    
    # Check if code is expired or used
    if time.time() > auth_data["expires_at"] or auth_data["used"]:
        raise HTTPException(status_code=400, detail="Authorization code expired or used")
    
    # Verify client and redirect URI match
    if auth_data["client_id"] != client_id or auth_data["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="Invalid client or redirect_uri")
    
    # Verify PKCE if present
    if auth_data["code_challenge"] and code_verifier:
        if not verify_pkce(code_verifier, auth_data["code_challenge"], auth_data["code_challenge_method"]):
            raise HTTPException(status_code=400, detail="Invalid code_verifier")
    
    # Mark code as used
    auth_data["used"] = True
    
    # Generate tokens
    scopes = auth_data["scope"].split()
    access_token = generate_access_token(auth_data["user_id"], client_id, scopes)
    refresh_token_value = generate_refresh_token()
    
    # Store tokens
    token_id = str(uuid.uuid4())
    access_tokens[access_token] = {
        "user_id": auth_data["user_id"],
        "client_id": client_id,
        "scopes": scopes,
        "expires_at": time.time() + 3600
    }
    
    refresh_tokens[refresh_token_value] = {
        "user_id": auth_data["user_id"],
        "client_id": client_id,
        "scopes": scopes,
        "access_token": access_token
    }
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token_value,
        "scope": auth_data["scope"]
    }

async def handle_client_credentials_grant(client_id: str, client_secret: str, scope: str):
    """Handle client credentials grant for machine-to-machine auth."""
    
    # Verify client
    if not verify_client(client_id, client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Use default scopes if none provided
    if not scope:
        scope = "customer:read ticket:create account:calculate"
    
    requested_scopes = scope.split()
    allowed_scopes = clients[client_id]["scopes"]
    
    # Verify client has requested scopes
    if not all(s in allowed_scopes for s in requested_scopes):
        raise HTTPException(status_code=400, detail="Invalid scope")
    
    # Generate access token for client
    access_token = generate_access_token(client_id, client_id, requested_scopes)
    
    # Store token
    access_tokens[access_token] = {
        "user_id": client_id,
        "client_id": client_id,
        "scopes": requested_scopes,
        "expires_at": time.time() + 3600
    }
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope
    }

async def handle_refresh_token_grant(client_id: str, client_secret: str, refresh_token: str):
    """Handle refresh token grant."""
    
    # Verify client
    if not verify_client(client_id, client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Verify refresh token
    if refresh_token not in refresh_tokens:
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    
    token_data = refresh_tokens[refresh_token]
    
    # Verify client matches
    if token_data["client_id"] != client_id:
        raise HTTPException(status_code=400, detail="Invalid client")
    
    # Revoke old access token
    old_access_token = token_data["access_token"]
    if old_access_token in access_tokens:
        del access_tokens[old_access_token]
    
    # Generate new access token
    new_access_token = generate_access_token(
        token_data["user_id"], client_id, token_data["scopes"]
    )
    
    # Update tokens
    access_tokens[new_access_token] = {
        "user_id": token_data["user_id"],
        "client_id": client_id,
        "scopes": token_data["scopes"],
        "expires_at": time.time() + 3600
    }
    
    token_data["access_token"] = new_access_token
    
    return {
        "access_token": new_access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(token_data["scopes"])
    }

@app.get("/userinfo")
async def userinfo(request: Request):
    """OAuth 2.1 userinfo endpoint."""
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = auth_header[7:]
    
    if token not in access_tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    token_data = access_tokens[token]
    
    if time.time() > token_data["expires_at"]:
        raise HTTPException(status_code=401, detail="Token expired")
    
    return {
        "sub": token_data["user_id"],
        "client_id": token_data["client_id"],
        "scope": " ".join(token_data["scopes"]),
        "active": True
    }

@app.post("/revoke")
async def revoke_token(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...)
):
    """Token revocation endpoint."""
    
    # Verify client
    if not verify_client(client_id, client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    
    # Revoke access token
    if token in access_tokens:
        del access_tokens[token]
    
    # Revoke refresh token
    if token in refresh_tokens:
        # Also revoke associated access token
        token_data = refresh_tokens[token]
        if token_data["access_token"] in access_tokens:
            del access_tokens[token_data["access_token"]]
        del refresh_tokens[token]
    
    return {"revoked": True}

@app.get("/debug/tokens")
async def debug_tokens():
    """Debug endpoint to view active tokens (development only)."""
    return {
        "access_tokens": len(access_tokens),
        "refresh_tokens": len(refresh_tokens),
        "authorization_codes": len(authorization_codes),
        "active_tokens": [
            {
                "user_id": data["user_id"],
                "client_id": data["client_id"],
                "scopes": data["scopes"],
                "expires_at": data["expires_at"]
            }
            for data in access_tokens.values()
        ]
    }

def main():
    """Run the OAuth 2.1 authorization server."""
    print("🔐 Starting OAuth 2.1 Authorization Server")
    print("=" * 50)
    print("🌐 Authorization URL: http://localhost:8080/authorize")
    print("🔑 Token URL: http://localhost:8080/token")
    print("ℹ️  Server Info: http://localhost:8080/")
    print("🐛 Debug Tokens: http://localhost:8080/debug/tokens")
    print("\n📋 Demo Clients:")
    for client_id in clients:
        print(f"   - {client_id}")
    print("\n👥 Demo Users:")
    for username in users:
        print(f"   - {username} / {users[username]['password']}")
    print("\n✅ OAuth server ready!")
    
    uvicorn.run(
        "oauth_server:app",
        host="127.0.0.1",
        port=8080,
        log_level="info"
    )

if __name__ == "__main__":
    main()