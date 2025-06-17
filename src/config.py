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

    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4.1-2025-04-14")

    # Anthropic Configuration
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    # Ollama Configuration
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma3:27b")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # Security Configuration
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-this-secret-key")
    OAUTH_CLIENT_ID: str = os.getenv("OAUTH_CLIENT_ID", "mcp-secure-client")
    OAUTH_CLIENT_SECRET: str = os.getenv("OAUTH_CLIENT_SECRET", "client-secret")
    OAUTH_AUTH_URL: str = os.getenv("OAUTH_AUTH_URL", "https://auth.example.com/authorize")
    OAUTH_TOKEN_URL: str = os.getenv("OAUTH_TOKEN_URL", "https://auth.example.com/token")
    
    # OAuth Server Configuration
    OAUTH_SERVER_HOST: str = os.getenv("OAUTH_SERVER_HOST", "localhost")
    OAUTH_SERVER_PORT: int = int(os.getenv("OAUTH_SERVER_PORT", "8080"))
    
    @classmethod
    def get_oauth_issuer_url(cls) -> str:
        """Get OAuth issuer URL."""
        return os.getenv("OAUTH_ISSUER_URL", f"http://{cls.OAUTH_SERVER_HOST}:{cls.OAUTH_SERVER_PORT}")

    # Server Configuration
    MCP_SERVER_HOST: str = os.getenv("MCP_SERVER_HOST", "localhost")
    MCP_SERVER_PORT: int = int(os.getenv("MCP_SERVER_PORT", "8000"))
    FORCE_HTTPS: bool = os.getenv("FORCE_HTTPS", "true").lower() == "true"

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
        """Validate configuration based on selected provider."""
        if cls.LLM_PROVIDER == "openai" and not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required when using OpenAI provider")
        elif cls.LLM_PROVIDER == "anthropic" and not cls.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY is required when using Anthropic provider"
            )

        if not cls.JWT_SECRET_KEY or cls.JWT_SECRET_KEY == "change-this-secret-key":
            raise ValueError("JWT_SECRET_KEY must be set to a secure value")
