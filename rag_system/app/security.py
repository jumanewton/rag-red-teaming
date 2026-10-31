"""
Security middleware:
  - API key authentication
  - Redis-backed rate limiting (token bucket)
  - Request/response audit logging (critical for red team forensics)
"""
import hashlib
import logging
import time
from typing import Optional

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status
from fastapi.security import APIKeyHeader

from .config import settings

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Rate limiter state ─────────────────────────────────────────────────────────
_redis_client: Optional[aioredis.Redis] = None


async def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def verify_api_key(api_key: Optional[str] = None) -> str:
    """
    Validates the X-API-Key header.
    Red teamers will try: missing key, wrong key, SQL injection in key, etc.
    """
    if not api_key or api_key != settings.api_key:
        logger.warning(f"❌ Auth failure — provided key: {repr(api_key)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key


async def rate_limit(request: Request, identifier: str) -> None:
    """
    Sliding window rate limiter using Redis INCR + EXPIRE.
    Limits to `settings.rate_limit_requests` per `settings.rate_limit_window` seconds.
    Red teamers will try to exhaust this (DoS) or slip under it.
    """
    try:
        client = await _get_redis()
        window_key = f"rate:{identifier}:{int(time.time()) // settings.rate_limit_window}"
        count = await client.incr(window_key)
        if count == 1:
            await client.expire(window_key, settings.rate_limit_window * 2)
        if count > settings.rate_limit_requests:
            logger.warning(f"🚨 Rate limit exceeded for {identifier}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Try again later.",
                headers={"Retry-After": str(settings.rate_limit_window)},
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rate limiter error (fail-open): {e}")


def hash_query(query: str) -> str:
    """Stable MD5 hash for cache key generation."""
    return hashlib.md5(query.encode()).hexdigest()


def audit_log(request: Request, query: str, response_summary: str, user_id: str) -> None:
    """
    Audit log — every query is logged for forensic analysis.
    This lets us track red team attack patterns.
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.info(
        f"AUDIT | user={user_id} | ip={client_ip} | "
        f"query={repr(query[:100])} | response={repr(response_summary[:80])}"
    )
