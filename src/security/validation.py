"""Input validation and sanitization module."""

import re
import bleach
from pydantic import BaseModel, field_validator, Field
from typing import List

class SecureTicketRequest(BaseModel):
    customer_id: str = Field(pattern=r"^[A-Z0-9]{5,10}$", description="Strict ID format")
    subject: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    priority: str

    @field_validator('subject', 'description')
    @classmethod
    def sanitize_text(cls, v):
        """Remove any potential injection attempts."""
        # Strip HTML and dangerous characters
        cleaned = bleach.clean(v, tags=[], strip=True)

        # Prevent command injection patterns
        dangerous_patterns = [
            r'<script',     # XSS attempts
            r'javascript:', # JavaScript injection
            r'DROP TABLE',  # SQL injection
            r'\$\{.*\}',    # Template injection
            r'`.*`',        # Command substitution
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, cleaned, flags=re.IGNORECASE):
                raise ValueError(f"Invalid characters detected: {pattern}")

        return cleaned.strip()

    @field_validator('priority')
    @classmethod
    def validate_priority(cls, v):
        """Ensure priority is from allowed list."""
        allowed_priorities = ['low', 'normal', 'high', 'urgent']
        if v not in allowed_priorities:
            raise ValueError(f"Priority must be one of {allowed_priorities}, got {v}")
        return v

class SecureCustomerRequest(BaseModel):
    customer_id: str = Field(pattern=r"^[A-Z0-9]{5,10}$")

class SecureCalculationRequest(BaseModel):
    customer_id: str = Field(pattern=r"^[A-Z0-9]{5,10}$")
    amounts: List[float] = Field(min_length=1, max_length=100)
    
    @field_validator('amounts')
    @classmethod
    def validate_amounts(cls, v):
        for amount in v:
            if amount < 0 or amount > 1000000:
                raise ValueError("Amount must be between 0 and 1,000,000")
        return v
