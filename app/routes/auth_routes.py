from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import (COOKIE_NAME, COOKIE_SECURE, SESSION_HOURS, authenticate,
                      create_session, delete_session, require_user)
from app.db import get_db
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=128)  # cap the size so nobody can send huge junk


@router.post("/login")
def login(body: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = authenticate(db, body.email, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_session(db, user)
    response.set_cookie(
        COOKIE_NAME, token,
        httponly=True,            # JavaScript can't read it (blocks theft via XSS)
        samesite="lax",           # other websites can't make your browser send it on POSTs
        secure=COOKIE_SECURE,     # HTTPS only when deployed
        max_age=SESSION_HOURS * 3600,
        path="/",
    )
    return {"email": user.email, "role": user.role}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        delete_session(db, token)
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "logged out"}


@router.get("/me")
def me(user: User = Depends(require_user)):
    return {"id": user.id, "email": user.email, "role": user.role}