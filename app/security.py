"""
Security utilities for the AI AppSec PR Reviewer.

Provides HMAC signature verification, rate limiting (in-memory and Redis-backed),
request ID tracing, and other enterprise security controls.
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
from collections import defaultdict
from typing import Optional
from contextvars import ContextVar, Token

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Context variable for request ID tracing
request_id_var: ContextVar[str] = ContextVar("request_id", default="")
request_timing_var: ContextVar[Optional[dict[str, float]]] = ContextVar("request_timing", default=None)


def get_request_id() -> str:
    """Get the current request ID from context."""
    return request_id_var.get()


def generate_request_id() -> str:
    """Generate a new unique request ID."""
    return str(uuid.uuid4())


def init_request_timing() -> Token:
    """Initialize per-request timing aggregation storage."""
    return request_timing_var.set({})


def clear_request_timing(token: Token) -> None:
    """Reset per-request timing aggregation storage."""
    request_timing_var.reset(token)


def add_request_timing(component: str, duration_ms: float) -> None:
    """Add timing in milliseconds for a named component in current request context."""
    timings = request_timing_var.get()
    if timings is None:
        return
    timings[component] = timings.get(component, 0.0) + duration_ms


def get_request_timing_breakdown() -> dict[str, float]:
    """Get a copy of the current request timing breakdown."""
    timings = request_timing_var.get()
    if not timings:
        return {}
    return dict(timings)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to add request ID to all requests for tracing."""
    
    async def dispatch(self, request: Request, call_next):
        # Check for existing request ID in header (from upstream proxy)
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = generate_request_id()
        
        # Set in context for use throughout the request
        token = request_id_var.set(request_id)
        
        try:
            response: Response = await call_next(request)
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_var.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""
    
    def __init__(self, app, settings=None):
        super().__init__(app)
        self.settings = settings
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Basic security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy (adjust based on your needs)
        cors_origin = request.headers.get("Origin", "")
        connect_src = f"'self' {cors_origin}".strip()
        
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            f"connect-src {connect_src}"
        )
        
        # Strict Transport Security (only if HTTPS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Remove sensitive headers (use del instead of pop for MutableHeaders)
        if "Server" in response.headers:
            del response.headers["Server"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        
        return response


class RateLimiter:
    """In-memory rate limiter (for development/single-instance deployments)."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
    
    def _clean_old_requests(self, key: str, now: float) -> None:
        """Remove expired requests from tracking."""
        cutoff = now - self.window_seconds
        self._requests[key] = [ts for ts in self._requests[key] if ts > cutoff]
    
    def is_allowed(self, key: str) -> bool:
        """Check if a request is allowed and record it."""
        now = time.time()
        self._clean_old_requests(key, now)
        
        if len(self._requests[key]) >= self.max_requests:
            return False
        
        self._requests[key].append(now)
        return True
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests for a key."""
        now = time.time()
        self._clean_old_requests(key, now)
        return max(0, self.max_requests - len(self._requests[key]))
    
    def get_reset_time(self, key: str) -> int:
        """Get seconds until rate limit resets."""
        if not self._requests[key]:
            return 0
        oldest = min(self._requests[key])
        return max(0, int(self.window_seconds - (time.time() - oldest)))


class RedisRateLimiter:
    """Redis-backed rate limiter for distributed/production deployments."""
    
    def __init__(self, redis_url: str, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._redis = None
        self._redis_url = redis_url
        self._connect()
    
    def _connect(self) -> None:
        """Connect to Redis."""
        try:
            import redis
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            logger.info("Redis rate limiter connected")
        except ImportError:
            logger.warning("redis package not installed, falling back to in-memory rate limiting")
            self._redis = None
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._redis = None
    
    def _get_key(self, identifier: str) -> str:
        """Generate Redis key for rate limiting."""
        return f"ratelimit:{identifier}"
    
    def is_allowed(self, key: str) -> bool:
        """Check if a request is allowed using sliding window."""
        if not self._redis:
            # Fail closed - if Redis is unavailable, we cannot verify rate limit
            # In production, you might want to use in-memory fallback instead
            logger.warning("Redis unavailable, rate limiting disabled - failing closed")
            return False
        
        try:
            redis_key = self._get_key(key)
            now = time.time()
            window_start = now - self.window_seconds
            
            # Use Redis pipeline for atomicity
            pipe = self._redis.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(redis_key, 0, window_start)
            
            # Count current entries
            pipe.zcard(redis_key)
            
            # Add new entry
            pipe.zadd(redis_key, {str(now): now})
            
            # Set expiration
            pipe.expire(redis_key, self.window_seconds)
            
            results = pipe.execute()
            current_count = results[1]
            
            return current_count < self.max_requests
        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            # Fail closed - don't allow requests if we can't verify rate limit
            return False
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests for a key."""
        if not self._redis:
            return self.max_requests
        
        try:
            redis_key = self._get_key(key)
            now = time.time()
            window_start = now - self.window_seconds
            
            # Count entries in current window
            count = self._redis.zcount(redis_key, window_start, now)
            return max(0, self.max_requests - count)
        except Exception as e:
            logger.error(f"Redis get_remaining error: {e}")
            return self.max_requests
    
    def get_reset_time(self, key: str) -> int:
        """Get seconds until rate limit resets."""
        if not self._redis:
            return 0
        
        try:
            redis_key = self._get_key(key)
            # Get oldest entry
            oldest = self._redis.zrange(redis_key, 0, 0, withscores=True)
            if oldest:
                oldest_time = oldest[0][1]
                return max(0, int(self.window_seconds - (time.time() - oldest_time)))
            return 0
        except Exception as e:
            logger.error(f"Redis get_reset_time error: {e}")
            return 0


# Global rate limiter instances
_rate_limiter: Optional[RateLimiter] = None
_token_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter(
    max_requests: int = 100,
    window_seconds: int = 3600,
    redis_url: Optional[str] = None
) -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        if redis_url:
            _rate_limiter = RedisRateLimiter(redis_url, max_requests, window_seconds)
        else:
            _rate_limiter = RateLimiter(max_requests, window_seconds)
    return _rate_limiter


def get_token_rate_limiter(
    max_requests: int = 10,
    window_seconds: int = 3600,
    redis_url: Optional[str] = None
) -> RateLimiter:
    """Get or create the token creation rate limiter."""
    global _token_rate_limiter
    if _token_rate_limiter is None:
        if redis_url:
            _token_rate_limiter = RedisRateLimiter(redis_url, max_requests, window_seconds)
        else:
            _token_rate_limiter = RateLimiter(max_requests, window_seconds)
    return _token_rate_limiter


def compute_hmac_signature(payload: str, secret: str, timestamp: int) -> str:
    """
    Compute HMAC-SHA256 signature for a payload.
    
    Args:
        payload: The JSON payload string
        secret: The shared secret
        timestamp: Unix timestamp
        
    Returns:
        Hex-encoded HMAC signature
    """
    message = f"{timestamp}.{payload}".encode('utf-8')
    signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_hmac_signature(
    payload: str,
    signature: str,
    timestamp: int,
    secret: str,
    tolerance_seconds: int = 300
) -> bool:
    """
    Verify an HMAC signature with timestamp validation.
    
    Args:
        payload: The JSON payload string
        signature: The provided signature to verify
        timestamp: The provided timestamp
        secret: The shared secret
        tolerance_seconds: Maximum age of request in seconds
        
    Returns:
        True if signature is valid
        
    Raises:
        HTTPException: If signature is invalid or request is too old
    """
    # Check timestamp is within tolerance
    now = int(time.time())
    if abs(now - timestamp) > tolerance_seconds:
        raise HTTPException(
            status_code=401,
            detail=f"Request timestamp is too old or in the future. "
                   f"Server time: {now}, Request time: {timestamp}"
        )
    
    # Compute expected signature
    expected = compute_hmac_signature(payload, secret, timestamp)
    
    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid HMAC signature"
        )
    
    return True


async def validate_request_security(
    request: Request,
    body: bytes,
    hmac_secret: Optional[str],
    hmac_tolerance: int,
    max_request_size: int,
    max_diff_size: int
) -> dict:
    """
    Validate all security aspects of a request.
    
    Args:
        request: The FastAPI request
        body: Raw request body
        hmac_secret: HMAC secret if enabled
        hmac_tolerance: Timestamp tolerance in seconds
        max_request_size: Maximum request body size
        max_diff_size: Maximum diff size
        
    Returns:
        Parsed request data
        
    Raises:
        HTTPException: If any validation fails
    """
    # Check request size
    if len(body) > max_request_size:
        raise HTTPException(
            status_code=413,
            detail=f"Request body too large. Maximum size: {max_request_size} bytes"
        )
    
    # Parse JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error: {e}. Body preview: {body[:200] if body else 'empty'}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid JSON in request body: {str(e)}"
        )
    
    # Check diff size
    diff = data.get("diff", "")
    if len(diff) > max_diff_size:
        raise HTTPException(
            status_code=413,
            detail=f"Diff too large. Maximum size: {max_diff_size} bytes"
        )
    
    # Verify HMAC signature if enabled
    if hmac_secret:
        signature = data.get("signature")
        timestamp = data.get("timestamp")
        
        logger.info(f"HMAC validation: secret_set={bool(hmac_secret)}, has_signature={bool(signature)}, has_timestamp={bool(timestamp)}")
        
        if not signature or not timestamp:
            logger.warning(f"HMAC validation failed: missing fields. signature={bool(signature)}, timestamp={bool(timestamp)}")
            raise HTTPException(
                status_code=401,
                detail="HMAC signature and timestamp are required"
            )
        
        # Remove signature fields from payload for verification
        payload_data = {k: v for k, v in data.items() if k not in ("signature", "timestamp")}
        payload_str = json.dumps(payload_data, sort_keys=True, separators=(',', ':'))
        
        verify_hmac_signature(
            payload=payload_str,
            signature=signature,
            timestamp=timestamp,
            secret=hmac_secret,
            tolerance_seconds=hmac_tolerance
        )
    
    return data


def get_client_identifier(request: Request) -> str:
    """
    Get a unique identifier for the client for rate limiting.
    
    Uses X-Forwarded-For header if present (for proxied requests),
    otherwise falls back to client IP.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct client IP
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Get the user agent from the request."""
    return request.headers.get("User-Agent", "unknown")


def sanitize_for_logging(data: dict) -> dict:
    """
    Sanitize request data for safe logging.
    
    Removes sensitive fields like diff content, signatures, etc.
    Only keeps metadata for audit logging.
    """
    return {
        "repo": data.get("repo"),
        "pr_number": data.get("pr_number"),
        "language": data.get("language"),
        "framework": data.get("framework"),
        "diff_size": len(data.get("diff", "")),
        "has_policy": data.get("policy") is not None,
        "has_signature": data.get("signature") is not None,
    }


def redact_sensitive_fields(data: dict, fields_to_redact: list[str]) -> dict:
    """
    Redact sensitive fields from a dictionary for logging.
    
    Args:
        data: Dictionary to redact
        fields_to_redact: List of field names to redact
        
    Returns:
        Dictionary with sensitive fields redacted
    """
    result = {}
    for key, value in data.items():
        if key in fields_to_redact:
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = redact_sensitive_fields(value, fields_to_redact)
        else:
            result[key] = value
    return result
