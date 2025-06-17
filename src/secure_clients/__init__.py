"""
Secure client implementations for various AI platforms.
Each client demonstrates how to connect securely to OAuth-protected MCP servers.
"""

from .openai_client import SecureOpenAIMCPClient

__all__ = ["SecureOpenAIMCPClient"]