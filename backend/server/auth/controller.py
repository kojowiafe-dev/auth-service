from fastapi import APIRouter, status
from loguru import logger

from server.auth.models import AuthBase, PasswordChange, OtpRequest
from server.database.core import SessionDep
from server.auth.service import AuthService
from server.dependencies import CurrentUser


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


@router.patch("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_change: PasswordChange,
    session: SessionDep,
    user: CurrentUser,
):
    logger.info(f"Changing password for user: {user.email_address}")
    return await AuthService(session=session).change_password(  
        password_change=password_change,
    )


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    request: AuthBase,
    session: SessionDep,
):
    logger.info(f"Forgot password request for user: {request.email_address}")
    return await AuthService(session=session).forgot_password(request=request)