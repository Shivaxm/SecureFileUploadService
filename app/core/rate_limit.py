from collections.abc import Callable
import time

import redis

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings


def _get_redis():
    return redis.Redis.from_url(settings.redis_url)


def _current_window(window_seconds: int) -> int:
    return int(time.time() // window_seconds)


def rate_limit_ip(route: str, limit: int, window_seconds: int):
    async def dependency(request: Request):
        redis_client = _get_redis()
        ip = request.client.host if request.client else "unknown"
        key = f"rl:ip:{ip}:{route}:{_current_window(window_seconds)}"
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, window_seconds)
        if count > limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    return dependency


def rate_limit_user(route: str, limit: int, window_seconds: int):
    async def dependency(request: Request):
        redis_client = _get_redis()
        user_id = getattr(getattr(request, "state", None), "user_id", None)
        if not user_id and hasattr(request, "user") and getattr(request.user, "id", None):
            user_id = request.user.id
        if not user_id:
            # fallback to client ip if no user context; still protect
            ip = request.client.host if request.client else "unknown"
            user_id = f"ip-{ip}"
        key = f"rl:user:{user_id}:{route}:{_current_window(window_seconds)}"
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, window_seconds)
        if count > limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    return dependency


class RateLimitMiddleware(BaseHTTPMiddleware):
    # Kept for compatibility; currently not enforcing per-request limits
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        return response

