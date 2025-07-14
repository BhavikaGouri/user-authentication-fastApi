import random

from fastapi import APIRouter, Depends, HTTPException
from slugify import slugify
from sqlmodel import Session, select

from app.auth.security import get_hash
from app.db.session import get_session
from app.models.user import User
from app.db.users import UserData

router = APIRouter()


@router.post("/signup")
async def add_user(new_user: UserData, session: Session = Depends(get_session)):
    statement = select(User).where(User.email == new_user.email)
    if session.exec(statement).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    while True:
        username = slugify(new_user.name) + str(random.randint(1, 100))
        if not session.get(User, username):
            break

    new_user = User(
        name=new_user.name,
        username=username,
        email=new_user.email,
        hashed_password=get_hash(new_user.password),
        disabled=False,
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"name": new_user.name, "username": username}
