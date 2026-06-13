"""
Redis connection pool — one shared pool for the entire process lifetime.

Architecture note:
  redis.asyncio uses an event-loop-native client. We create the pool once
  at module import time and share it. This avoids the overhead of opening a
  new TCP connection on every request (each connection takes ~1-2 ms).

  RedisDep is a FastAPI dependency (Annotated type) that yields the pool
  directly — it does NOT open/close a connection each time; the pool manages
  that internally.
"""

import redis.asyncio as aioredis
from typing import Annotated
from fastapi import Depends

from server.config import settings


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------
# decode_responses=True  →  Redis returns Python str, not bytes.
# max_connections=20     →  cap the pool; tune per your deployment.
# ---------------------------------------------------------------------------
_pool = aioredis.ConnectionPool.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    max_connections=20,
)

redis_client = aioredis.Redis(connection_pool=_pool)


async def get_redis() -> aioredis.Redis:
    """FastAPI dependency — yields the shared Redis client."""
    return redis_client


RedisDep = Annotated[aioredis.Redis, Depends(get_redis)]
