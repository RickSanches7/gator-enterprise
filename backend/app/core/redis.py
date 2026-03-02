"""GATOR PRO — Redis connection check"""
async def check_redis_connection() -> bool:
    from app.core.config import settings
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=3)
        await r.ping()
        await r.aclose()
        return True
    except Exception:
        return False
