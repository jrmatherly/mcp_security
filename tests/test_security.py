"""Security tests for MCP server."""

import pytest

from src.security.monitoring import SecurityLogger
from src.security.rate_limiting import RateLimiter
from src.security.validation import SecureTicketRequest


class TestInputValidation:
    """Test input validation and sanitization."""

    def test_valid_ticket_request(self):
        """Test valid ticket request passes validation."""
        request = SecureTicketRequest(
            customer_id="12345",
            subject="Billing Issue",
            description="I was charged twice for my order",
            priority="high",
        )
        assert request.customer_id == "12345"
        assert request.subject == "Billing Issue"
        assert request.priority == "high"

    def test_invalid_customer_id(self):
        """Test invalid customer ID format is rejected."""
        with pytest.raises(ValueError):
            SecureTicketRequest(
                customer_id="invalid-id!",
                subject="Test",
                description="Test description",
                priority="normal",
            )

    def test_injection_attempt_blocked(self):
        """Test command injection attempts are blocked."""
        with pytest.raises(ValueError):
            SecureTicketRequest(
                customer_id="12345",
                subject="Test; DROP TABLE customers; --",
                description="Normal description",
                priority="normal",
            )

    def test_invalid_priority(self):
        """Test invalid priority is rejected."""
        with pytest.raises(ValueError):
            SecureTicketRequest(
                customer_id="12345",
                subject="Test",
                description="Test description",
                priority="invalid_priority",
            )


class TestRateLimiting:
    """Test rate limiting functionality."""

    @pytest.mark.asyncio
    async def test_request_rate_limit_memory(self):
        """Test request rate limiting with memory backend."""
        rate_limiter = RateLimiter(requests_per_minute=2)

        # First two requests should pass
        result1 = await rate_limiter.check_rate_limit("user1")
        assert result1 is None

        result2 = await rate_limiter.check_rate_limit("user1")
        assert result2 is None

        # Third request should be rate limited
        result3 = await rate_limiter.check_rate_limit("user1")
        assert result3 is not None
        assert result3["limit_type"] == "requests"

    @pytest.mark.asyncio
    async def test_token_rate_limit_memory(self):
        """Test token rate limiting with memory backend."""
        rate_limiter = RateLimiter(token_limit_per_hour=100)

        # Request within limit should pass
        result1 = await rate_limiter.check_rate_limit("user1", estimated_tokens=50)
        assert result1 is None

        # Request that would exceed limit should fail
        result2 = await rate_limiter.check_rate_limit("user1", estimated_tokens=60)
        assert result2 is not None
        assert result2["limit_type"] == "tokens"


class TestSecurityLogging:
    """Test security monitoring functionality."""

    def test_security_event_logging(self):
        """Test security event logging."""
        monitor = SecurityLogger()

        monitor.log_security_event("test_event", {"key": "value"})

        assert len(monitor.events) == 1
        assert monitor.events[0]["type"] == "test_event"
        assert monitor.events[0]["details"]["key"] == "value"

    def test_failed_auth_logging(self):
        """Test failed authentication logging."""
        monitor = SecurityLogger()

        monitor.log_failed_auth("user123", "invalid_token", "192.168.1.1")

        assert len(monitor.events) == 1
        assert monitor.events[0]["type"] == "authentication_failed"
        assert monitor.events[0]["details"]["user_id"] == "user123"

    def test_security_summary(self):
        """Test security summary generation."""
        monitor = SecurityLogger()

        monitor.log_security_event("event1", {})
        monitor.log_security_event("event1", {})
        monitor.log_security_event("event2", {})

        summary = monitor.get_security_summary()

        assert summary["total_events"] == 3
        assert summary["event_types"]["event1"] == 2
        assert summary["event_types"]["event2"] == 1
