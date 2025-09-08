"""
FastMCP 2.8+ compatible secure server with OAuth authentication for HTTP transport.
"""

from contextlib import asynccontextmanager
from datetime import datetime
import logging
import os
import time
from typing import Any, Dict

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.azure import AzureProvider
from fastmcp.server.dependencies import AccessToken, get_access_token

from config import Config
from security.jwt_verifier import azure_jwt_verifier
from security.monitoring import SecurityLogger
from security.rate_limiting import RateLimiter
from security.validation import (
    SecureCalculationRequest,
    SecureCustomerRequest,
    SecureTicketRequest,
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
rate_limiter = RateLimiter()
security_logger = SecurityLogger()


def create_azure_auth_provider():
    """Create Azure OAuth Provider using FastMCP's native Azure integration."""
    # Get Azure configuration from environment
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        raise ValueError(
            "Missing Azure configuration. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET"
        )

    # Use FastMCP's native Azure provider
    return AzureProvider(
        client_id=client_id,
        client_secret=client_secret,
        tenant_id=tenant_id,
        base_url=Config.AZURE_BASE_URL,
        required_scopes=Config.AZURE_DEFAULT_SCOPES,
    )


# Create Azure OAuth Provider for authentication
try:
    auth_provider = create_azure_auth_provider()
    logger.info("✅ Azure OAuth Provider configured for Entra ID")
except ValueError as e:
    logger.warning(f"⚠️  {e}")
    logger.warning(
        "⚠️  Running without authentication - configure Azure credentials first!"
    )
    auth_provider = None
except Exception as e:
    logger.error(f"❌ Failed to configure Azure OAuth Provider: {e}")
    auth_provider = None


@asynccontextmanager
async def lifespan(app):
    """Lifespan handler - replaces @mcp.on_event()"""
    logger.info("🔐 Starting secure MCP server with OAuth...")

    # Validate Azure configuration on startup
    try:
        Config.validate_azure_config()
        logger.info("✅ Azure OAuth configuration validated")
    except ValueError as e:
        logger.warning(f"⚠️  Azure configuration issue: {e}")

    # Set demo JWT secret if not provided (deprecated for OAuth Proxy)
    if not os.environ.get("JWT_SECRET_KEY"):
        os.environ["JWT_SECRET_KEY"] = "demo-secret-change-in-production"
        logger.warning(
            "⚠️  JWT_SECRET_KEY not set - OAuth Proxy handles token verification"
        )

    logger.info("✅ Server startup complete")
    yield  # Server runs here

    logger.info("🔐 Server shutdown complete")


# Initialize FastMCP with lifespan and auth parameters
mcp = FastMCP(
    name="Secure Customer Service",
    instructions="Demo secure MCP server with OAuth authentication. Available tools: get_customer_info, create_support_ticket, calculate_account_value",
    lifespan=lifespan,
    auth=auth_provider,
)


def _get_required_scopes(tool_name: str) -> list[str]:
    """Map tool names to required OAuth scopes - Azure Graph API format."""
    scope_mapping = {
        "get_customer_info": ["https://graph.microsoft.com/.default"],
        "create_support_ticket": ["https://graph.microsoft.com/.default"],
        "calculate_account_value": ["https://graph.microsoft.com/.default"],
        "get_recent_customers": ["https://graph.microsoft.com/.default"],
    }
    return scope_mapping.get(tool_name, [])


async def _check_tool_permissions(tool_name: str) -> None:
    """Check if current token has required scopes for the tool with enhanced validation."""
    try:
        # Get the validated access token from FastMCP
        access_token: AccessToken = await get_access_token()

        # Enhanced token validation
        if not access_token:
            security_logger.error(f"No access token found for {tool_name}")
            raise ToolError(f"Authentication required for {tool_name}")

        # Get required scopes for this tool
        required_scopes = _get_required_scopes(tool_name)

        # Extract scopes from token with enhanced parsing
        token_scopes = getattr(access_token, "scopes", [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()

        # Log token information for debugging (excluding sensitive data)
        security_logger.debug(
            f"Token scopes for {tool_name}: {len(token_scopes)} scopes present"
        )

        # Check token expiration if available
        if hasattr(access_token, "expires_at"):
            current_time = time.time()
            if access_token.expires_at and current_time > access_token.expires_at:
                security_logger.warning(f"Expired token used for {tool_name}")
                raise ToolError(
                    f"Token expired for {tool_name}. Please re-authenticate."
                )

        # Check if token has all required scopes
        missing_scopes = [
            scope for scope in required_scopes if scope not in token_scopes
        ]

        if missing_scopes:
            security_logger.warning(
                f"Access denied to {tool_name}: missing scopes {missing_scopes}"
            )
            raise ToolError(
                f"Insufficient permissions for {tool_name}. Missing scopes: {missing_scopes}"
            )

        # Log successful permission check
        security_logger.info(
            f"Access granted to {tool_name}: {len(required_scopes)} scopes verified"
        )

        # Additional rate limiting check
        user_id = str(getattr(access_token, "sub", "unknown"))
        await rate_limiter.check_limits(user_id)

    except ToolError:
        # Re-raise ToolError as-is
        raise
    except Exception as e:
        # If we can't get the token or verify scopes, deny access
        security_logger.error(f"Permission check failed for {tool_name}: {e}")
        raise ToolError(
            f"Permission verification failed for {tool_name}: Authentication error"
        )


@mcp.tool
async def get_customer_info(customer_id: str) -> Dict[str, Any]:
    """Get customer information with validation.

    Args:
        customer_id: Customer ID (5-10 alphanumeric characters, e.g., 'ABC123')

    Returns:
        Customer information including name, status, and last activity
    """
    # Check permissions first (server-side scope validation)
    await _check_tool_permissions("get_customer_info")

    try:
        request = SecureCustomerRequest(customer_id=customer_id)
        security_logger.info(f"Retrieved customer info for {request.customer_id}")

        return {
            "customer_id": request.customer_id,
            "name": f"Customer {request.customer_id}",
            "status": "active",
            "account_type": "premium",
            "last_activity": datetime.now().isoformat(),
            "contact_info": {
                "email": f"customer{request.customer_id.lower()}@example.com",
                "phone": "+1-555-0123",
            },
        }
    except Exception as e:
        logger.error(f"Customer lookup failed: {e}")
        raise ValueError(f"Invalid customer request: {e}")


@mcp.tool
async def create_support_ticket(
    customer_id: str, subject: str, description: str, priority: str
) -> Dict[str, Any]:
    """Create support ticket with validation.

    Args:
        customer_id: Customer ID (5-10 alphanumeric characters)
        subject: Ticket subject (1-200 characters)
        description: Ticket description (1-2000 characters)
        priority: Priority level ('low', 'normal', 'high', 'urgent')

    Returns:
        Created ticket information with ticket ID and details
    """
    # Check permissions first (server-side scope validation)
    await _check_tool_permissions("create_support_ticket")

    try:
        request = SecureTicketRequest(
            customer_id=customer_id,
            subject=subject,
            description=description,
            priority=priority,
        )

        ticket_id = f"TKT-{int(time.time())}-{customer_id[:3]}"
        security_logger.info(
            f"Created ticket {ticket_id} for customer {request.customer_id}"
        )

        return {
            "ticket_id": ticket_id,
            "customer_id": request.customer_id,
            "subject": request.subject,
            "description": request.description,
            "priority": request.priority,
            "status": "open",
            "created": datetime.now().isoformat(),
            "estimated_resolution": "24-48 hours"
            if request.priority in ["high", "urgent"]
            else "2-5 business days",
        }
    except Exception as e:
        logger.error(f"Ticket creation failed: {e}")
        raise ValueError(f"Invalid ticket request: {e}")


@mcp.tool
async def calculate_account_value(
    customer_id: str, amounts: list[float]
) -> Dict[str, Any]:
    """Calculate account value with validation.

    Args:
        customer_id: Customer ID (5-10 alphanumeric characters)
        amounts: List of purchase amounts (1-100 amounts, each 0-1,000,000)

    Returns:
        Account value calculation including total, average, and statistics
    """
    # Check permissions first (server-side scope validation)
    await _check_tool_permissions("calculate_account_value")

    try:
        request = SecureCalculationRequest(customer_id=customer_id, amounts=amounts)

        total = sum(request.amounts)
        average = total / len(request.amounts) if request.amounts else 0
        max_amount = max(request.amounts) if request.amounts else 0
        min_amount = min(request.amounts) if request.amounts else 0

        security_logger.info(
            f"Calculated account value for customer {request.customer_id}"
        )

        return {
            "customer_id": request.customer_id,
            "calculation": {
                "total": round(total, 2),
                "average": round(average, 2),
                "count": len(request.amounts),
                "max_purchase": round(max_amount, 2),
                "min_purchase": round(min_amount, 2),
                "amounts": request.amounts,
            },
            "account_tier": "gold"
            if total > 50000
            else "silver"
            if total > 10000
            else "bronze",
            "calculated_at": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Calculation failed: {e}")
        raise ValueError(f"Invalid calculation request: {e}")


@mcp.resource("health://status")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint to verify server status."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "authentication": "azure_oauth_proxy",
        "features": [
            "azure_oauth_proxy",
            "input_validation",
            "security_logging",
            "rate_limiting",
        ],
    }


# Server health resource (FastMCP 2.8+ pattern)
@mcp.resource("server://health")
async def server_health() -> Dict[str, Any]:
    """Server health check resource for client connectivity."""
    return {
        "status": "healthy",
        "authentication": "azure_oauth_proxy",
        "oauth_endpoints": {
            "authorization": "/auth/authorize",
            "token": "/auth/token",
            "callback": "/auth/callback",
            "userinfo": "/auth/userinfo",
        },
        "azure_config": {
            "tenant_id": os.environ.get("AZURE_TENANT_ID", "<not_configured>"),
            "client_id": os.environ.get("AZURE_CLIENT_ID", "<not_configured>"),
            "base_url": Config.AZURE_BASE_URL,
        },
        "timestamp": datetime.now().isoformat(),
    }


@mcp.resource("oauth://config")
async def oauth_info() -> Dict[str, Any]:
    """OAuth configuration information resource."""
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    if not tenant_id:
        return {"error": "Azure configuration not found"}

    return {
        "provider": "Microsoft Azure (Entra ID)",
        "authorization_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "jwks_uri": f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        "issuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "scopes_supported": [
            "https://graph.microsoft.com/.default",
            "User.Read",
            "email",
            "openid",
            "profile",
        ],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "pkce_required": True,
    }


@mcp.resource("security://events")
async def get_security_events() -> Dict[str, Any]:
    """Get security events for monitoring purposes."""
    return {
        "total_events": 0,
        "recent_events": [],
        "summary": {"errors": 0, "warnings": 0, "info": 0},
        "monitoring_status": "active",
        "retrieved_at": datetime.now().isoformat(),
    }


@mcp.tool
async def validate_token() -> Dict[str, Any]:
    """Validate current OAuth token and return user information.

    Returns:
        Token validation status and user information
    """
    try:
        # Get current access token
        access_token: AccessToken = await get_access_token()

        if not access_token:
            return {
                "valid": False,
                "error": "No access token found",
                "timestamp": datetime.now().isoformat(),
            }

        # Extract token string (assuming access_token has a token attribute)
        token_string = getattr(access_token, "token", str(access_token))

        # Use enhanced JWT verifier for additional validation
        try:
            decoded_token = await azure_jwt_verifier.verify_azure_token(token_string)
            user_info = await azure_jwt_verifier.extract_user_info(decoded_token)

            return {
                "valid": True,
                "user_info": user_info,
                "token_claims": {
                    "issuer": decoded_token.get("iss"),
                    "audience": decoded_token.get("aud"),
                    "expires_at": decoded_token.get("exp"),
                    "issued_at": decoded_token.get("iat"),
                    "not_before": decoded_token.get("nbf"),
                },
                "validation_timestamp": datetime.now().isoformat(),
            }

        except Exception as verification_error:
            security_logger.warning(f"Token verification failed: {verification_error}")
            return {
                "valid": False,
                "error": f"Token verification failed: {str(verification_error)}",
                "timestamp": datetime.now().isoformat(),
            }

    except Exception as e:
        security_logger.error(f"Token validation error: {e}")
        return {
            "valid": False,
            "error": f"Validation error: {str(e)}",
            "timestamp": datetime.now().isoformat(),
        }


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

    host = Config.MCP_SERVER_HOST
    port = Config.MCP_SERVER_PORT

    print("🔒 Starting Secure Customer Service MCP Server with OAuth")
    print("📋 Available Tools:")
    print("   - get_customer_info(customer_id)")
    print("   - create_support_ticket(customer_id, subject, description, priority)")
    print("   - calculate_account_value(customer_id, amounts)")
    print("📊 Available Resources:")
    print("   - health://status")
    print("   - security://events")
    print("🔐 OAuth Authentication: Required (Bearer token)")
    print(f"\n🌐 Running HTTP server on {host}:{port}")

    try:
        mcp.run(transport="streamable-http", host=host, port=port)
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped gracefully")
        print("\n🔐 Server shutdown complete")
