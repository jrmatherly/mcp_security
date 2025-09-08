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

    # Azure Configuration (for OAuth Proxy)
    AZURE_TENANT_ID: Optional[str] = os.getenv("AZURE_TENANT_ID")
    AZURE_CLIENT_ID: Optional[str] = os.getenv("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET: Optional[str] = os.getenv("AZURE_CLIENT_SECRET")

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
