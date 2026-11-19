import redis.asyncio as redis

from app.core.config import get_settings

_pool: redis.ConnectionPool | None = None


def get_redis() -> redis.Redis:
    """Dependency FastAPI: Depends(get_redis)."""
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(get_settings().redis_url, decode_responses=True, max_connections=50)
    return redis.Redis(connection_pool=_pool)


async def close_redis() -> None:
    global _pool
    if _pool is not None:
        await _pool.disconnect()
        _pool = None
