from sqlmodel import SQLModel
from .session import engine

def create_db_and_table():
    SQLModel.metadata.create_all(engine)
