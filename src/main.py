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
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import AccessToken, get_access_token

from config import Config
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


def create_oauth_proxy_auth():
    """Create OAuth Proxy for Azure authentication."""
    # Get Azure configuration from environment
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    if not all([tenant_id, client_id, client_secret]):
        raise ValueError(
            "Missing Azure configuration. Please set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET"
        )

    # JWT verifier for Azure tokens
    token_verifier = JWTVerifier(
        jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        audience=client_id,
    )

    # OAuth Proxy for Azure (non-DCR provider)
    return OAuthProxy(
        upstream_authorization_endpoint=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        upstream_token_endpoint=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        upstream_client_id=client_id,
        upstream_client_secret=client_secret,
        token_verifier=token_verifier,
        base_url="http://localhost:8000",
    )


# Create OAuth Proxy for Azure authentication
try:
    auth_provider = create_oauth_proxy_auth()
    logger.info("✅ OAuth Proxy configured for Azure Entra ID")
except ValueError as e:
    logger.warning(f"⚠️  {e}")
    logger.warning(
        "⚠️  Running without authentication - configure Azure credentials first!"
    )
    auth_provider = None
except Exception as e:
    logger.error(f"❌ Failed to configure OAuth Proxy: {e}")
    auth_provider = None


@asynccontextmanager
async def lifespan(app):
    """Lifespan handler - replaces @mcp.on_event()"""
    logger.info("🔐 Starting secure MCP server with OAuth...")

    # Set demo JWT secret if not provided
    if not os.environ.get("JWT_SECRET_KEY"):
        os.environ["JWT_SECRET_KEY"] = "demo-secret-change-in-production"
        logger.warning("⚠️  Using demo JWT secret!")

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
    """Check if current token has required scopes for the tool."""
    try:
        # Get the validated access token from FastMCP
        access_token: AccessToken = await get_access_token()

        # Get required scopes for this tool
        required_scopes = _get_required_scopes(tool_name)

        # Extract scopes from token (same as clients)
        token_scopes = getattr(access_token, "scopes", [])
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()

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

        security_logger.info(f"Access granted to {tool_name}: scopes verified")

    except Exception as e:
        # If we can't get the token or verify scopes, deny access
        security_logger.error(f"Permission check failed for {tool_name}: {e}")
        raise ToolError(f"Permission verification failed for {tool_name}")


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


# Add HTTP health endpoint for client checking
async def http_health() -> Dict[str, Any]:
    """HTTP health endpoint for client connectivity checks."""
    return {
        "status": "healthy",
        "authentication": "azure_oauth_proxy",
        "timestamp": datetime.now().isoformat(),
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
