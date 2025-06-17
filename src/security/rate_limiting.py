"""Mock rate limiting module for development."""

import time
from typing import Dict, Optional, DefaultDict
from collections import defaultdict

class RateLimiter:
    """Simple in-memory rate limiter for testing."""
    
    def __init__(self, requests_per_minute: int = 60, token_limit_per_hour: int = 100000, redis_client=None, **kwargs):
        self.requests_per_minute = requests_per_minute
        self.token_limit_per_hour = token_limit_per_hour
        self.redis_client = redis_client
        
        # In-memory storage for rate limiting
        self.request_counts: DefaultDict[str, list] = defaultdict(list)
        self.token_counts: DefaultDict[str, list] = defaultdict(list)
    
    async def check_rate_limit(self, user_id: str, estimated_tokens: int = 0) -> Optional[Dict]:
        """Check rate limits - returns None if allowed, dict with error if rate limited."""
        current_time = time.time()
        
        # Clean old entries and check request rate limit
        minute_ago = current_time - 60
        self.request_counts[user_id] = [
            timestamp for timestamp in self.request_counts[user_id] 
            if timestamp > minute_ago
        ]
        
        if len(self.request_counts[user_id]) >= self.requests_per_minute:
            return {
                "error": "Rate limit exceeded",
                "limit_type": "requests",
                "retry_after": 60
            }
        
        # Check token rate limit if tokens specified
        if estimated_tokens > 0:
            hour_ago = current_time - 3600
            self.token_counts[user_id] = [
                (timestamp, tokens) for timestamp, tokens in self.token_counts[user_id]
                if timestamp > hour_ago
            ]
            
            total_tokens = sum(tokens for _, tokens in self.token_counts[user_id])
            if total_tokens + estimated_tokens > self.token_limit_per_hour:
                return {
                    "error": "Token rate limit exceeded", 
                    "limit_type": "tokens",
                    "retry_after": 3600
                }
            
            # Record token usage
            self.token_counts[user_id].append((current_time, estimated_tokens))
        
        # Record request
        self.request_counts[user_id].append(current_time)
        
        return None