"""Configuration module for secure MCP server."""

import os
from typing import Optional

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Configuration class for secure MCP server."""

    # LLM Provider
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai")

    # Azure OAuth Proxy Configuration
    AZURE_TENANT_ID: Optional[str] = os.getenv("AZURE_TENANT_ID")
    AZURE_CLIENT_ID: Optional[str] = os.getenv("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET: Optional[str] = os.getenv("AZURE_CLIENT_SECRET")

    # FastMCP Server Authentication Configuration
    FASTMCP_SERVER_AUTH: str = os.getenv("FASTMCP_SERVER_AUTH", "azure")
    FASTMCP_SERVER_AUTH_AZURE_CLIENT_ID: Optional[str] = os.getenv(
        "FASTMCP_SERVER_AUTH_AZURE_CLIENT_ID"
    )
    FASTMCP_SERVER_AUTH_AZURE_TENANT_ID: Optional[str] = os.getenv(
        "FASTMCP_SERVER_AUTH_AZURE_TENANT_ID"
    )
    FASTMCP_SERVER_AUTH_AZURE_BASE_URL: str = os.getenv(
        "FASTMCP_SERVER_AUTH_AZURE_BASE_URL", "http://localhost:8000"
    )

    # Azure OAuth Endpoints (constructed from tenant ID)
    @classmethod
    def get_azure_authorization_endpoint(cls) -> str:
        """Get Azure OAuth authorization endpoint."""
        if not cls.AZURE_TENANT_ID:
            raise ValueError("AZURE_TENANT_ID is required for OAuth endpoints")
        return f"https://login.microsoftonline.com/{cls.AZURE_TENANT_ID}/oauth2/v2.0/authorize"

    @classmethod
    def get_azure_token_endpoint(cls) -> str:
        """Get Azure OAuth token endpoint."""
        if not cls.AZURE_TENANT_ID:
            raise ValueError("AZURE_TENANT_ID is required for OAuth endpoints")
        return (
            f"https://login.microsoftonline.com/{cls.AZURE_TENANT_ID}/oauth2/v2.0/token"
        )

    @classmethod
    def get_azure_jwks_uri(cls) -> str:
        """Get Azure JWKS URI for token verification."""
        if not cls.AZURE_TENANT_ID:
            raise ValueError("AZURE_TENANT_ID is required for JWKS URI")
        return f"https://login.microsoftonline.com/{cls.AZURE_TENANT_ID}/discovery/v2.0/keys"

    @classmethod
    def get_azure_issuer(cls) -> str:
        """Get Azure token issuer."""
        if not cls.AZURE_TENANT_ID:
            raise ValueError("AZURE_TENANT_ID is required for issuer")
        return f"https://login.microsoftonline.com/{cls.AZURE_TENANT_ID}/v2.0"

    # Azure OAuth Scopes
    AZURE_DEFAULT_SCOPES: list[str] = [
        "https://graph.microsoft.com/.default",
        "User.Read",
        "email",
        "openid",
        "profile",
    ]

    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_BASE_URL: Optional[str] = os.getenv("OPENAI_BASE_URL")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4.1-2025-04-14")

    # Anthropic Configuration
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    # Ollama Configuration
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma3:27b")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # Note: OAuth Server variables removed - server now uses Azure OAuth Proxy

    # Server Configuration
    MCP_SERVER_HOST: str = os.getenv("MCP_SERVER_HOST", "localhost")
    MCP_SERVER_PORT: int = int(os.getenv("MCP_SERVER_PORT", "8000"))
    FORCE_HTTPS: bool = os.getenv("FORCE_HTTPS", "true").lower() == "true"

    # FastMCP Azure Base URL Configuration (FastMCP Standard)
    # Development: http://localhost:8000
    # Production: https://api.example.com
    # Docker/nginx: https://localhost:8443
    # Note: This now uses the properly defined FASTMCP variable above
    AZURE_BASE_URL: str = FASTMCP_SERVER_AUTH_AZURE_BASE_URL

    @classmethod
    def get_mcp_oauth_url(cls) -> str:
        """Get MCP OAuth endpoint URL for FastMCP OAuth clients."""
        return f"{cls.AZURE_BASE_URL}/mcp"

    @classmethod
    def get_mcp_server_url(cls) -> str:
        """Get MCP server endpoint URL."""
        return f"{cls.AZURE_BASE_URL}/mcp"

    # Rate Limiting
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = int(
        os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60")
    )
    RATE_LIMIT_TOKENS_PER_HOUR: int = int(
        os.getenv("RATE_LIMIT_TOKENS_PER_HOUR", "100000")
    )

    # TLS Configuration
    TLS_CERT_PATH: str = os.getenv("TLS_CERT_PATH", "./certificates/server.crt")
    TLS_KEY_PATH: str = os.getenv("TLS_KEY_PATH", "./certificates/server.key")

    # Monitoring
    SECURITY_LOGGING: bool = os.getenv("SECURITY_LOGGING", "true").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls) -> None:
        """Validate configuration based on selected provider and OAuth setup."""
        # Validate LLM provider configuration
        if cls.LLM_PROVIDER == "openai" and not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required when using OpenAI provider")
        elif cls.LLM_PROVIDER == "anthropic" and not cls.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY is required when using Anthropic provider"
            )

        # Validate Azure OAuth configuration
        cls.validate_azure_config()

    @classmethod
    def validate_azure_config(cls) -> None:
        """Validate Azure OAuth configuration."""
        # Check if using FastMCP authentication
        if cls.FASTMCP_SERVER_AUTH == "azure":
            # Validate FastMCP Azure variables
            required_fastmcp_vars = [
                (
                    "FASTMCP_SERVER_AUTH_AZURE_TENANT_ID",
                    cls.FASTMCP_SERVER_AUTH_AZURE_TENANT_ID,
                ),
                (
                    "FASTMCP_SERVER_AUTH_AZURE_CLIENT_ID",
                    cls.FASTMCP_SERVER_AUTH_AZURE_CLIENT_ID,
                ),
            ]

            missing_fastmcp_vars = [
                var_name
                for var_name, var_value in required_fastmcp_vars
                if not var_value
            ]

            if missing_fastmcp_vars:
                raise ValueError(
                    f"Missing required FastMCP Azure configuration: {', '.join(missing_fastmcp_vars)}. "
                    "Please configure FastMCP Azure credentials."
                )

        # Also validate legacy Azure variables for backward compatibility
        required_azure_vars = [
            ("AZURE_TENANT_ID", cls.AZURE_TENANT_ID),
            ("AZURE_CLIENT_ID", cls.AZURE_CLIENT_ID),
            ("AZURE_CLIENT_SECRET", cls.AZURE_CLIENT_SECRET),
        ]

        missing_vars = [
            var_name for var_name, var_value in required_azure_vars if not var_value
        ]

        if missing_vars:
            raise ValueError(
                f"Missing required Azure configuration: {', '.join(missing_vars)}. "
                "Please configure Azure App Registration credentials."
            )

    @classmethod
    def get_oauth_redirect_uri(cls) -> str:
        """Get OAuth redirect URI for Azure App Registration."""
        return f"{cls.AZURE_BASE_URL}/auth/callback"

    @classmethod
    def get_fastmcp_oauth_endpoints(cls) -> dict:
        """Get FastMCP OAuth endpoints for client configuration."""
        return {
            "mcp_url": f"{cls.AZURE_BASE_URL}/mcp",
            "register_url": f"{cls.AZURE_BASE_URL}/register",
            "authorize_url": f"{cls.AZURE_BASE_URL}/authorize",
            "token_url": f"{cls.AZURE_BASE_URL}/token",
            "callback_url": f"{cls.AZURE_BASE_URL}/auth/callback",
        }

    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment."""
        return (
            cls.AZURE_BASE_URL.startswith("https://")
            and "localhost" not in cls.AZURE_BASE_URL
        )
