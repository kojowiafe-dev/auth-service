from fastapi import APIRouter, status
from loguru import logger

from server.auth.models import AuthBase
from server.database.core import SessionDep
from server.auth.service import AuthService


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    request: AuthBase,
    session: SessionDep,
):
    logger.info(f"Registering user: {request.email_address}")
    return await AuthService(session=session).register(request=request)


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
    request: AuthBase,
    session: SessionDep,
):
    logger.info(f"Logging in user: {request.email_address}")
    return await AuthService(session=session).login(request=request)