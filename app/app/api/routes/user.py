from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from app.models.user import User
from app.db.session import get_session
from app.auth.security import get_hash
import random

router = APIRouter()

@router.post("/signup")
async def add_user(session: Session = Depends(get_session), name: str = "", password: str = "", email: str = ""):
    statement = select(User).where(User.email == email)
    if session.exec(statement).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    while True:
        username = name + str(random.randint(1, 100))
        if not session.get(User, username):
            break

    new_user = User(
        name=name,
        username=username,
        email=email,
        hashed_password=get_hash(password),
        disabled=False
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"name": name, "username": username}