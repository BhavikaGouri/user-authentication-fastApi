from sqlmodel import SQLModel, Field, Session, create_engine, select
from passlib.context import CryptContext
from typing import Generator
import random


SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

hash_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

connect_args = {"check_same_thread": False}
engine = create_engine("sqlite:///orm-user.db", connect_args=connect_args)


class User(SQLModel, table=True):
    name: str
    username: str | None = Field(default=None, primary_key=True)
    email: str | None = Field(default=None)
    hashed_password: str | None = Field(default=None)
    disabled: bool | None = Field(default=None)


def create_db_and_table():
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator:
    with Session(engine) as session:
        yield session


def get_hash(password: str) -> str:
    return hash_context.hash(password)

def verify_password(hashed_password, password):
    return hash_context.verify(password, hashed_password)

def generate_unique_username(name: str, session: Session) -> str:
    while True:
        username = name + str(random.randint(1, 100))
        statement = select(User).where(User.username == username)
        if not session.exec(statement).first():
            return username

