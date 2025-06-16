from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field, Session, SQLModel, create_engine, select
import random
from contextlib import asynccontextmanager

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

hash_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Oauth2Scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()


class User(SQLModel, table=True):
    name: str
    username: str | None = Field(default=None, primary_key=True)
    email: str | None = Field(default=None)
    hashed_password: str | None = Field(default=None)
    disabled: bool | None = Field(default=None)


connect_args = {"check_same_thread": False}
engine = create_engine("sqlite:///orm-user.db", connect_args=connect_args)


def create_db_and_table():
    SQLModel.metadata.create_all(engine)


@asynccontextmanager
async def lifespan(app):
    # Startup logic
    create_db_and_table()
    yield
    # (Optional) Shutdown logic


app = FastAPI(lifespan=lifespan)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def get_hash(password):
    return hash_context.hash(password)


def verify_password(hashed_password, password):
    return hash_context.verify(password, hashed_password)


def authenticate_user(username: str, session: SessionDep, password: str):
    user = session.get(User, username)
    if user.username != username:
        return False
    if not verify_password(user.hashed_password, password):
        return False
    return True


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc)  + expires_delta
    else:
        expire = datetime.now(timezone.utc)  + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


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
    if user is None or user.username != username:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/signup")
async def add_user(session: SessionDep, name: str, password: str, email: str):
    new_user = User()
    new_user.name = name

    statement = select(User).where(User.email == email)
    result = session.exec(statement).first()
    if not result:
        new_user.email = email
    else:
        raise HTTPException(status_code=404, detail="email already exists")
    while 1:
        new_user.username = name + str(random.randint(1, 100))
        statement = select(User).where(User.username == new_user.username)
        result = session.exec(statement).first()
        if not result:
            break

    new_user.hashed_password = get_hash(password)
    new_user.disabled = False
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"name": name, "username": new_user.username}


@app.post("/login")
async def login(session: SessionDep, form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, session, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    user = session.get(User, form_data.username)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user