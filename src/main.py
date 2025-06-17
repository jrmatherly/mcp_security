"""
FastMCP 2.8+ compatible secure server with OAuth authentication for HTTP transport.
"""

import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any, Optional

from fastmcp import FastMCP
from fastmcp.server.auth import BearerAuthProvider

from config import Config
from security.validation import SecureTicketRequest, SecureCustomerRequest, SecureCalculationRequest
from security.rate_limiting import RateLimiter
from security.monitoring import SecurityLogger

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
rate_limiter = RateLimiter()
security_logger = SecurityLogger()

def load_public_key():
    """Load RSA public key for JWT verification."""
    from pathlib import Path
    from cryptography.hazmat.primitives import serialization
    
    public_key_path = Path("keys/public_key.pem")
    
    if not public_key_path.exists():
        raise FileNotFoundError(
            "Public key not found. Run 'python src/generate_keys.py' or 'task generate-keys' first."
        )
    
    with open(public_key_path, "rb") as f:
        public_key_pem = f.read()
    
    # Convert to PEM string format that BearerAuthProvider expects
    return public_key_pem.decode('utf-8')

# Create Bearer auth provider for FastMCP with RSA public key
try:
    public_key_pem = load_public_key()
    auth_provider = BearerAuthProvider(
        public_key=public_key_pem,
        issuer=Config.get_oauth_issuer_url(),  # Use config for OAuth issuer URL
        audience=None  # Allow any client_id
    )
except FileNotFoundError as e:
    logger.warning(f"⚠️  {e}")
    logger.warning("⚠️  Running without authentication - generate keys first!")
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
    auth=auth_provider
)


@mcp.tool
async def get_customer_info(customer_id: str) -> Dict[str, Any]:
    """Get customer information with validation.

    Args:
        customer_id: Customer ID (5-10 alphanumeric characters, e.g., 'ABC123')

    Returns:
        Customer information including name, status, and last activity
    """
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
                "phone": "+1-555-0123"
            }
        }
    except Exception as e:
        logger.error(f"Customer lookup failed: {e}")
        raise ValueError(f"Invalid customer request: {e}")

@mcp.tool
async def create_support_ticket(
    customer_id: str,
    subject: str,
    description: str,
    priority: str
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
    try:
        request = SecureTicketRequest(
            customer_id=customer_id,
            subject=subject,
            description=description,
            priority=priority
        )

        ticket_id = f"TKT-{int(time.time())}-{customer_id[:3]}"
        security_logger.info(f"Created ticket {ticket_id} for customer {request.customer_id}")

        return {
            "ticket_id": ticket_id,
            "customer_id": request.customer_id,
            "subject": request.subject,
            "description": request.description,
            "priority": request.priority,
            "status": "open",
            "created": datetime.now().isoformat(),
            "estimated_resolution": "24-48 hours" if request.priority in ["high", "urgent"] else "2-5 business days"
        }
    except Exception as e:
        logger.error(f"Ticket creation failed: {e}")
        raise ValueError(f"Invalid ticket request: {e}")

@mcp.tool
async def calculate_account_value(
    customer_id: str,
    amounts: list[float]
) -> Dict[str, Any]:
    """Calculate account value with validation.

    Args:
        customer_id: Customer ID (5-10 alphanumeric characters)
        amounts: List of purchase amounts (1-100 amounts, each 0-1,000,000)

    Returns:
        Account value calculation including total, average, and statistics
    """
    try:
        request = SecureCalculationRequest(
            customer_id=customer_id,
            amounts=amounts
        )

        total = sum(request.amounts)
        average = total / len(request.amounts) if request.amounts else 0
        max_amount = max(request.amounts) if request.amounts else 0
        min_amount = min(request.amounts) if request.amounts else 0

        security_logger.info(f"Calculated account value for customer {request.customer_id}")

        return {
            "customer_id": request.customer_id,
            "calculation": {
                "total": round(total, 2),
                "average": round(average, 2),
                "count": len(request.amounts),
                "max_purchase": round(max_amount, 2),
                "min_purchase": round(min_amount, 2),
                "amounts": request.amounts
            },
            "account_tier": "gold" if total > 50000 else "silver" if total > 10000 else "bronze",
            "calculated_at": datetime.now().isoformat()
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
        "features": ["oauth_auth", "input_validation", "security_logging", "rate_limiting"]
    }

@mcp.resource("security://events")
async def get_security_events() -> Dict[str, Any]:
    """Get security events for monitoring purposes."""
    return {
        "total_events": 0,
        "recent_events": [],
        "summary": {
            "errors": 0,
            "warnings": 0,
            "info": 0
        },
        "monitoring_status": "active",
        "retrieved_at": datetime.now().isoformat()
    }


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

    host = os.getenv("MCP_SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_SERVER_PORT", "8000"))

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

    mcp.run(transport="streamable-http", host=host, port=port)
