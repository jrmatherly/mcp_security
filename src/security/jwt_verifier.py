"""
Enhanced JWT token verification for Azure OAuth integration.
Provides comprehensive token validation with Azure-specific features.
"""

import logging
import time
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt

from config import Config

logger = logging.getLogger(__name__)


class AzureJWTVerifier:
    """Enhanced JWT verifier for Azure OAuth tokens with comprehensive validation."""

    def __init__(self):
        self.jwks_cache = {}
        self.jwks_cache_expiry = 0
        self.cache_duration = 3600  # 1 hour

    async def get_jwks(self, jwks_uri: str) -> Dict[str, Any]:
        """Fetch JWKS with caching for performance."""
        current_time = time.time()

        # Check cache
        if jwks_uri in self.jwks_cache and current_time < self.jwks_cache_expiry:
            return self.jwks_cache[jwks_uri]

        # Fetch fresh JWKS
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(jwks_uri, timeout=10.0)
                response.raise_for_status()
                jwks_data = response.json()

                # Cache the JWKS
                self.jwks_cache[jwks_uri] = jwks_data
                self.jwks_cache_expiry = current_time + self.cache_duration

                logger.debug(f"✅ JWKS fetched and cached from {jwks_uri}")
                return jwks_data

            except Exception as e:
                logger.error(f"❌ Failed to fetch JWKS from {jwks_uri}: {e}")

                # Return cached version if available, even if expired
                if jwks_uri in self.jwks_cache:
                    logger.warning("⚠️  Using expired JWKS cache due to fetch failure")
                    return self.jwks_cache[jwks_uri]

                raise Exception(f"Unable to fetch JWKS: {e}")

    def get_public_key(self, jwks_data: Dict[str, Any], kid: str) -> str:
        """Extract public key from JWKS for given key ID."""
        keys = jwks_data.get("keys", [])

        for key in keys:
            if key.get("kid") == kid and key.get("kty") == "RSA":
                # Extract RSA key components
                n = self._base64url_decode(key["n"])
                e = self._base64url_decode(key["e"])

                # Create RSA public key
                public_numbers = rsa.RSAPublicNumbers(
                    e=int.from_bytes(e, byteorder="big"),
                    n=int.from_bytes(n, byteorder="big"),
                )
                public_key = public_numbers.public_key()

                # Convert to PEM format
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                return pem.decode()

        raise Exception(f"Public key not found for kid: {kid}")

    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url encoded data."""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding

        return jwt.utils.base64url_decode(data)

    async def verify_azure_token(
        self, token: str, validate_audience: bool = True
    ) -> Dict[str, Any]:
        """
        Verify Azure OAuth token with comprehensive validation.

        Args:
            token: JWT token to verify
            validate_audience: Whether to validate token audience

        Returns:
            Decoded token payload if valid

        Raises:
            Exception: If token is invalid
        """
        try:
            # Decode token header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                raise Exception("Token missing 'kid' claim")

            # Get JWKS and extract public key
            jwks_uri = Config.get_azure_jwks_uri()
            jwks_data = await self.get_jwks(jwks_uri)
            public_key = self.get_public_key(jwks_data, kid)

            # Prepare verification options
            verification_options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": validate_audience,
                "verify_iss": True,
                "require_exp": True,
                "require_iat": True,
            }

            # Verify token
            decoded_token = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=Config.AZURE_CLIENT_ID if validate_audience else None,
                issuer=Config.get_azure_issuer(),
                options=verification_options,
            )

            # Additional Azure-specific validations
            await self._validate_azure_claims(decoded_token)

            logger.debug("✅ Token verification successful")
            return decoded_token

        except jwt.ExpiredSignatureError:
            logger.warning("⚠️  Token has expired")
            raise Exception("Token expired")
        except jwt.InvalidAudienceError:
            logger.warning("⚠️  Invalid token audience")
            raise Exception("Invalid token audience")
        except jwt.InvalidIssuerError:
            logger.warning("⚠️  Invalid token issuer")
            raise Exception("Invalid token issuer")
        except jwt.InvalidSignatureError:
            logger.warning("⚠️  Invalid token signature")
            raise Exception("Invalid token signature")
        except Exception as e:
            logger.error(f"❌ Token verification failed: {e}")
            raise Exception(f"Token verification failed: {e}")

    async def _validate_azure_claims(self, decoded_token: Dict[str, Any]) -> None:
        """Perform additional Azure-specific claim validations."""
        # Check token version
        ver = decoded_token.get("ver")
        if ver not in ["1.0", "2.0"]:
            logger.warning(f"⚠️  Unexpected token version: {ver}")

        # Validate application ID if present
        appid = decoded_token.get("appid")
        if appid and appid != Config.AZURE_CLIENT_ID:
            logger.warning(f"⚠️  Token appid {appid} doesn't match client ID")

        # Check tenant ID if available
        tid = decoded_token.get("tid")
        if tid and tid != Config.AZURE_TENANT_ID:
            logger.warning(f"⚠️  Token tenant {tid} doesn't match configured tenant")

        # Validate authentication method reference
        amr = decoded_token.get("amr", [])
        if not amr:
            logger.debug("ℹ️  No authentication method reference in token")

        logger.debug("✅ Azure-specific claim validation passed")

    async def extract_user_info(self, decoded_token: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user information from decoded Azure token."""
        user_info = {
            "user_id": decoded_token.get("sub") or decoded_token.get("oid"),
            "email": decoded_token.get("email") or decoded_token.get("upn"),
            "name": decoded_token.get("name"),
            "given_name": decoded_token.get("given_name"),
            "family_name": decoded_token.get("family_name"),
            "tenant_id": decoded_token.get("tid"),
            "app_id": decoded_token.get("appid"),
            "scopes": decoded_token.get("scp", "").split()
            if decoded_token.get("scp")
            else [],
            "roles": decoded_token.get("roles", []),
            "issued_at": decoded_token.get("iat"),
            "expires_at": decoded_token.get("exp"),
        }

        # Clean up None values
        return {k: v for k, v in user_info.items() if v is not None}


# Singleton instance for reuse
azure_jwt_verifier = AzureJWTVerifier()
