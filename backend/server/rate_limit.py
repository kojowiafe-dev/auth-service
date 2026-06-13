"""
Sliding-window rate limiter backed by Redis.

Architecture — how sliding-window rate limiting works:
─────────────────────────────────────────────────────
  Key schema: rl:{prefix}:{identifier}
    e.g.      rl:login:192.168.1.1

  On every request:
    1.  INCR  key         → atomically add 1, get back new count
    2.  If count == 1     → first request in window, set EXPIRE = window_seconds
    3.  If count > limit  → reject with HTTP 429, include Retry-After header

  Why a Lua script?
    INCR and EXPIRE are two separate commands. Without Lua, another process
    could INCR between our INCR and EXPIRE, and the EXPIRE would reset the
    window mid-flight. The Lua script runs atomically on the Redis server —
    no other command can interleave.

  Response headers added:
    X-RateLimit-Limit     → max requests allowed
    X-RateLimit-Remaining → requests left in current window
    X-RateLimit-Reset     → seconds until the window resets
    Retry-After           → same as Reset, standard HTTP header for 429s
"""

import time
from collections import defaultdict
from fastapi import HTTPException, status, Request, Response
from loguru import logger
import redis.asyncio as aioredis
from redis.exceptions import RedisError

from server.redis_client import RedisDep


# In-memory storage for rate limiter fallback when Redis is unavailable
_in_memory_cache: dict[str, list[float]] = defaultdict(list)


# ---------------------------------------------------------------------------
# Lua script — runs atomically on Redis, no round-trip race conditions
# ---------------------------------------------------------------------------
_INCR_AND_EXPIRE_SCRIPT = """
local key     = KEYS[1]
local limit   = tonumber(ARGV[1])
local window  = tonumber(ARGV[2])

local count   = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, window)
end

local ttl = redis.call('TTL', key)
return {count, ttl}
"""


class RateLimiter:
    """
    Dependency-injectable rate limiter.

    Usage in a route:
        @router.post("/login")
        async def login(
            request: Request,
            response: Response,
            _: None = Depends(RateLimiter(max_requests=10, window_seconds=60, prefix="login")),
            ...
        ):
    """

    def __init__(self, max_requests: int, window_seconds: int, prefix: str = "global"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.prefix = prefix

    async def __call__(
        self,
        request: Request,
        response: Response,
        redis: RedisDep,
    ) -> None:
        # ── Identify the client ──────────────────────────────────────────────
        # Prefer X-Forwarded-For (set by reverse proxies like Nginx/ALB).
        # Fall back to the direct connection IP.
        forwarded_for = request.headers.get("X-Forwarded-For")
        ip = forwarded_for.split(",")[0].strip() if forwarded_for else (
            request.client.host if request.client else "unknown"
        )

        key = f"rl:{self.prefix}:{ip}"

        # ── Run the atomic Lua script ────────────────────────────────────────
        try:
            result = await redis.eval(_INCR_AND_EXPIRE_SCRIPT, 1, key, self.max_requests, self.window_seconds)  # type: ignore[attr-defined]
            count, ttl = int(result[0]), int(result[1])
        except RedisError as e:
            logger.warning(f"Redis is unavailable ({type(e).__name__}: {e}). Falling back to in-memory rate limiting.")
            now = time.time()
            timestamps = _in_memory_cache[key]
            cutoff = now - self.window_seconds
            timestamps = [t for t in timestamps if t > cutoff]
            _in_memory_cache[key] = timestamps

            count = len(timestamps) + 1
            if count <= self.max_requests:
                timestamps.append(now)

            if timestamps:
                ttl = max(1, int(self.window_seconds - (now - timestamps[0])))
            else:
                ttl = self.window_seconds

        remaining = max(0, self.max_requests - count)

        # ── Set informational headers on every response ──────────────────────
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(ttl)

        # ── Enforce the limit ────────────────────────────────────────────────
        if count > self.max_requests:
            response.headers["Retry-After"] = str(ttl)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many requests. You have exceeded the limit of "
                    f"{self.max_requests} requests per {self.window_seconds} seconds. "
                    f"Try again in {ttl} seconds."
                ),
                headers={"Retry-After": str(ttl)},
            )
