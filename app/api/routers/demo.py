import uuid

from fastapi import APIRouter, Depends, Response

from app.api import deps
from app.core.config import settings
from app.core.rate_limit import rate_limit_ip

router = APIRouter()

_RL_DEMO_START_DEP = Depends(rate_limit_ip("demo_start", 10, 60))


@router.post("/start")
async def start_demo(response: Response, _: None = _RL_DEMO_START_DEP):
    demo_id = str(uuid.uuid4())
    token = deps.create_demo_token(demo_id, expires_in=deps.DEMO_COOKIE_MAX_AGE_SECONDS)
    response.set_cookie(
        key=deps.DEMO_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.app_env == "prod",
        max_age=deps.DEMO_COOKIE_MAX_AGE_SECONDS,
    )
    # TODO: Add scheduled cleanup to delete expired demo files from storage and DB.
    return {"ok": True}
