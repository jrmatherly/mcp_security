"""Mock authentication module for development."""

from typing import Dict

class MockOAuth2Scheme:
    """Mock OAuth2 scheme for development."""
    
    def __call__(self, *args, **kwargs):
        return "demo_token"

oauth2_scheme = MockOAuth2Scheme()

async def validate_token(token: str = None) -> Dict:
    """Validate token and return user info."""
    return {
        "user_id": "demo_user", 
        "scopes": ["customer:read", "ticket:create", "account:calculate"]
    }