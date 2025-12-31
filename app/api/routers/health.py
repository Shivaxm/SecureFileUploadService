from fastapi import APIRouter

router = APIRouter()


@router.get("/live")
async def live():
    return {"status": "ok"}


@router.get("/ready")
async def ready():
    # TODO: check DB, Redis, MinIO connectivity
    return {"status": "degraded", "details": "readiness checks not implemented"}

