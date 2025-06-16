from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from typing import Annotated

from database import (
    User, create_db_and_table, get_session, get_hash, verify_password,
    generate_unique_username, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
)

from sqlmodel import Session, select

Oauth2Scheme = OAuth2PasswordBearer(tokenUrl="login")
SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI()


@app.on_event("startup")
def on_startup():
    create_db_and_table()


def authenticate_user(username: str, session: Session, password: str):
    user = session.get(User, username)
    if not user:
        return False
    if not verify_password(user.hashed_password, password):
        return False
    return True


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(session: SessionDep, token: str = Depends(Oauth2Scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = session.get(User, username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/signup")
async def add_user(session: SessionDep, name: str, password: str, email: str):
    statement = select(User).where(User.email == email)
    if session.exec(statement).first():
        raise HTTPException(status_code=404, detail="email already exists")

    new_user = User(
        name=name,
        email=email,
        username=generate_unique_username(name, session),
        hashed_password=get_hash(password),
        disabled=False
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"name": name, "username": new_user.username}


@app.post("/login")
async def login(session: SessionDep, form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, session, form_data.password):

