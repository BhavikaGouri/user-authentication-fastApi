from fastapi import FastAPI
from app.api.routes import user, login, profile
from app.db.init_db import create_db_and_table

app = FastAPI()
app.include_router(profile.router, tags=["Auth Profile"])
app.include_router(user.router, tags=["Users"])
app.include_router(login.router, tags=["Auth"])

@app.on_event("startup")
def on_startup():
    create_db_and_table()