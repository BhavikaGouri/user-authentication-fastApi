from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    name: str
    username: str | None = Field(default=None, primary_key=True)
    email: str | None = Field(default=None)
    hashed_password: str | None = Field(default=None)
    disabled: bool | None = Field(default=None)
