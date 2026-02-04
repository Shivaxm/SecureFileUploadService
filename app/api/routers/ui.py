from fastapi import APIRouter, Request

from app.web import templates

router = APIRouter()


@router.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/upload")
async def upload(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})


@router.get("/architecture")
async def architecture(request: Request):
    return templates.TemplateResponse("architecture.html", {"request": request})
