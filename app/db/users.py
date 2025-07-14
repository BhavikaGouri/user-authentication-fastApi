from pydantic import BaseModel


class UserData(BaseModel):
    name: str
    email: str
    password: str
