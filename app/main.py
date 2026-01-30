from fastapi import FastAPI, HTTPException

from app.api.routers import auth, files, health
from app.core.config import settings
from app.core.logging import configure_logging
from app.core.rate_limit import RateLimitMiddleware

configure_logging()


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, debug=settings.debug)
    app.state.settings = settings

    app.add_middleware(RateLimitMiddleware)

    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(files.router, prefix="/files", tags=["files"])

    @app.get("/_not_implemented")
    async def not_implemented():
        raise HTTPException(status_code=501, detail="Not implemented")

    return app


app = create_app()
