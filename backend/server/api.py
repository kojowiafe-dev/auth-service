from fastapi import FastAPI

from server.auth.controller import router as auth_router
from server.users.controller import router as user_router


def register_routes(app: FastAPI):
    app.include_router(auth_router)
    app.include_router(user_router)

