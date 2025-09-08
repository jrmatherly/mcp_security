#!/usr/bin/env python3
"""
OAuth Proxy Implementation Validation Script

Tests the systematic OAuth Proxy implementation for FastMCP Azure integration.
"""

import asyncio
from pathlib import Path
import sys

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))

import httpx

from config import Config
from security.jwt_verifier import azure_jwt_verifier


class OAuthImplementationValidator:
    """Validates OAuth Proxy implementation components."""

    def __init__(self):
        self.validation_results = []

    def log_result(self, test_name: str, success: bool, message: str = ""):
        """Log validation result."""
        status = "✅ PASS" if success else "❌ FAIL"
        self.validation_results.append((test_name, success, message))
        print(f"{status}: {test_name}")
        if message:
            print(f"        {message}")

    def validate_environment_config(self):
        """Validate environment configuration."""
        print("\n🔧 ENVIRONMENT CONFIGURATION VALIDATION")
        print("=" * 50)

        # Check Azure credentials
        azure_vars = {
            "AZURE_TENANT_ID": Config.AZURE_TENANT_ID,
            "AZURE_CLIENT_ID": Config.AZURE_CLIENT_ID,
            "AZURE_CLIENT_SECRET": Config.AZURE_CLIENT_SECRET,
        }

        for var_name, var_value in azure_vars.items():
            if var_value and var_value != f"your-{var_name.lower().replace('_', '-')}":
                self.log_result(
                    f"{var_name} configured", True, f"Value: {var_value[:8]}..."
                )
            else:
                self.log_result(
                    f"{var_name} configured", False, "Not set or using placeholder"
                )

        # Check base URL configuration
        self.log_result(
            "AZURE_BASE_URL configured", True, f"URL: {Config.AZURE_BASE_URL}"
        )

        # Test configuration validation
        try:
            Config.validate_azure_config()
            self.log_result(
                "Azure configuration validation", True, "All required variables present"
            )
        except ValueError as e:
            self.log_result("Azure configuration validation", False, str(e))

    def validate_oauth_endpoints(self):
        """Validate OAuth endpoint construction."""
        print("\n🔗 OAUTH ENDPOINT VALIDATION")
        print("=" * 50)

        try:
            # Test endpoint factory methods
            auth_endpoint = Config.get_azure_authorization_endpoint()
            token_endpoint = Config.get_azure_token_endpoint()
            jwks_uri = Config.get_azure_jwks_uri()
            issuer = Config.get_azure_issuer()
            redirect_uri = Config.get_oauth_redirect_uri()

            self.log_result("Authorization endpoint", True, auth_endpoint)
            self.log_result("Token endpoint", True, token_endpoint)
            self.log_result("JWKS URI", True, jwks_uri)
            self.log_result("Token issuer", True, issuer)
            self.log_result("Redirect URI", True, redirect_uri)

        except Exception as e:
            self.log_result("OAuth endpoint construction", False, str(e))

    async def validate_jwks_access(self):
        """Validate JWKS access for token verification."""
        print("\n🔑 JWKS ACCESS VALIDATION")
        print("=" * 50)

        try:
            jwks_uri = Config.get_azure_jwks_uri()

            # Test JWKS fetching
            jwks_data = await azure_jwt_verifier.get_jwks(jwks_uri)

            if "keys" in jwks_data and len(jwks_data["keys"]) > 0:
                self.log_result(
                    "JWKS fetching", True, f"Retrieved {len(jwks_data['keys'])} keys"
                )

                # Check for RSA keys
                rsa_keys = [key for key in jwks_data["keys"] if key.get("kty") == "RSA"]
                if rsa_keys:
                    self.log_result(
                        "RSA keys available", True, f"Found {len(rsa_keys)} RSA keys"
                    )

                    # Test key extraction
                    try:
                        first_key = rsa_keys[0]
                        kid = first_key.get("kid", "test-key")
                        _ = azure_jwt_verifier.get_public_key(jwks_data, kid)
                        self.log_result(
                            "Public key extraction",
                            True,
                            "Successfully extracted PEM key",
                        )
                    except Exception as key_error:
                        self.log_result("Public key extraction", False, str(key_error))
                else:
                    self.log_result("RSA keys available", False, "No RSA keys found")
            else:
                self.log_result("JWKS fetching", False, "No keys returned")

        except Exception as e:
            self.log_result("JWKS access", False, str(e))

    async def validate_server_connectivity(self):
        """Validate server connectivity and health endpoints."""
        print("\n🌐 SERVER CONNECTIVITY VALIDATION")
        print("=" * 50)

        base_url = Config.AZURE_BASE_URL

        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                # Test health endpoint
                try:
                    health_response = await client.get(f"{base_url}/health")
                    if health_response.status_code == 200:
                        health_data = health_response.json()
                        self.log_result(
                            "Health endpoint",
                            True,
                            f"Status: {health_data.get('status')}",
                        )

                        # Check OAuth endpoints in health response
                        oauth_endpoints = health_data.get("oauth_endpoints", {})
                        if oauth_endpoints:
                            self.log_result(
                                "OAuth endpoints in health",
                                True,
                                f"Found: {', '.join(oauth_endpoints.keys())}",
                            )
                        else:
                            self.log_result(
                                "OAuth endpoints in health", False, "No OAuth endpoints"
                            )
                    else:
                        self.log_result(
                            "Health endpoint",
                            False,
                            f"HTTP {health_response.status_code}",
                        )
                except Exception as health_error:
                    self.log_result(
                        "Health endpoint", False, f"Connection failed: {health_error}"
                    )

                # Test OAuth info endpoint
                try:
                    oauth_info_response = await client.get(f"{base_url}/auth/info")
                    if oauth_info_response.status_code == 200:
                        oauth_info = oauth_info_response.json()
                        self.log_result(
                            "OAuth info endpoint",
                            True,
                            f"Provider: {oauth_info.get('provider')}",
                        )

                        # Check PKCE requirement
                        pkce_required = oauth_info.get("pkce_required", False)
                        self.log_result(
                            "PKCE configuration",
                            pkce_required,
                            f"PKCE required: {pkce_required}",
                        )
                    else:
                        self.log_result(
                            "OAuth info endpoint",
                            False,
                            f"HTTP {oauth_info_response.status_code}",
                        )
                except Exception as oauth_error:
                    self.log_result(
                        "OAuth info endpoint",
                        False,
                        f"Connection failed: {oauth_error}",
                    )

        except Exception as e:
            self.log_result("Server connectivity", False, str(e))

    def validate_configuration_classes(self):
        """Validate configuration classes and methods."""
        print("\n⚙️  CONFIGURATION CLASS VALIDATION")
        print("=" * 50)

        # Test Config class methods
        config_methods = [
            ("get_oauth_token_url", Config.get_oauth_token_url),
            ("get_mcp_server_url", Config.get_mcp_server_url),
            ("is_production", Config.is_production),
        ]

        for method_name, method in config_methods:
            try:
                result = method()
                self.log_result(f"Config.{method_name}()", True, f"Returns: {result}")
            except Exception as e:
                self.log_result(f"Config.{method_name}()", False, str(e))

        # Test Azure scope configuration
        if hasattr(Config, "AZURE_DEFAULT_SCOPES"):
            scopes = Config.AZURE_DEFAULT_SCOPES
            self.log_result(
                "Azure default scopes", True, f"Configured: {len(scopes)} scopes"
            )
        else:
            self.log_result("Azure default scopes", False, "Not configured")

    def print_summary(self):
        """Print validation summary."""
        print("\n📊 VALIDATION SUMMARY")
        print("=" * 50)

        total_tests = len(self.validation_results)
        passed_tests = sum(1 for _, success, _ in self.validation_results if success)
        failed_tests = total_tests - passed_tests

        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")

        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for test_name, success, message in self.validation_results:
                if not success:
                    print(f"  - {test_name}: {message}")

        print(
            f"\n🎯 Implementation Status: {'✅ READY' if failed_tests == 0 else '⚠️ NEEDS ATTENTION'}"
        )


async def main():
    """Run OAuth Proxy implementation validation."""
    print("🔐 OAuth Proxy Implementation Validation")
    print("=" * 50)
    print("Testing FastMCP Azure integration implementation...")

    validator = OAuthImplementationValidator()

    # Run validation tests
    validator.validate_environment_config()
    validator.validate_oauth_endpoints()
    await validator.validate_jwks_access()
    await validator.validate_server_connectivity()
    validator.validate_configuration_classes()

    # Print summary
    validator.print_summary()

    failed_tests = [
        test for test, success, _ in validator.validation_results if not success
    ]
    return len(failed_tests) == 0


if __name__ == "__main__":
    # Load environment variables
    from dotenv import load_dotenv

    load_dotenv()

    success = asyncio.run(main())
    sys.exit(0 if success else 1)
