from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import redis


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_url: str):
        super().__init__(app)
        self.redis = redis.Redis.from_url(redis_url)

    async def dispatch(self, request: Request, call_next: Callable):
        # TODO: implement real rate limiting with tokens or sliding window
        key = f"rl:{request.client.host}"
        self.redis.incr(key, 1)
        self.redis.expire(key, 60)
        response: Response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = "TODO"
        return response

