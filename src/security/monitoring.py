"""Mock security monitoring module for development."""

from collections import defaultdict
from datetime import datetime
import logging
from typing import Any, Dict, List


class SecurityLogger:
    """Mock security logger for development."""

    def __init__(self, name: str = "security"):
        self.logger = logging.getLogger(name)
        self.events: List[Dict[str, Any]] = []

    def info(self, message: str, **kwargs):
        """Log info message."""
        self.logger.info(message)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(message)

    def error(self, message: str, **kwargs):
        """Log error message."""
        self.logger.error(message)

    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log a security event."""
        event = {
            "type": event_type,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        }
        self.events.append(event)
        self.logger.info(f"Security event: {event_type} - {details}")

    def log_failed_auth(self, user_id: str, reason: str, ip_address: str):
        """Log failed authentication attempt."""
        details = {"user_id": user_id, "reason": reason, "ip_address": ip_address}
        self.log_security_event("authentication_failed", details)

    def get_security_summary(self) -> Dict[str, Any]:
        """Get security events summary."""
        event_types = defaultdict(int)
        for event in self.events:
            event_types[event["type"]] += 1

        return {
            "total_events": len(self.events),
            "event_types": dict(event_types),
            "last_updated": datetime.now().isoformat(),
        }
