from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api import deps
from app.core.security import create_access_token
from app.db import models

router = APIRouter()


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register")
async def register(payload: RegisterRequest, db: Session = Depends(deps.get_db)):
    # TODO: hash password, create user, assign default role
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Register not implemented")


@router.post("/login")
async def login(payload: LoginRequest, db: Session = Depends(deps.get_db)):
    # TODO: verify credentials
    fake_user = db.query(models.User).filter_by(email=payload.email).first()
    if not fake_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token({"sub": str(fake_user.id)})
    return {"access_token": token, "token_type": "bearer"}

