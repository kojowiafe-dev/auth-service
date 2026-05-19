from fastapi import APIRouter, status
from loguru import logger

from server.users.models import UserResponse, PasswordChange
from server.users.service import UserService
from server.dependencies import get_current_user
from server.database.core import SessionDep

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get(
    "",
    response_model=list[UserResponse],
    status_code=status.HTTP_200_OK
)
async def get_all_users(
    session: SessionDep
):
    return await UserService(session=session).get_users()


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK
)
async def get_current_user_route(
    session: SessionDep
):
    user = await get_current_user(session)
    logger.info(f"Getting current user: {user.email_address}")
    return {
        "id": user.id,
        "email": user.email_address,
    }


@router.put(
    "/change-password",
    status_code=status.HTTP_200_OK
)
async def change_password(
    password_change: PasswordChange,
    session: SessionDep,
):
    user = await get_current_user(session)
    logger.info(f"Changing password for user: {user.email_address}")
    await UserService(session=session).change_password(
        user_id=user.id,
        password_change=password_change
    )
    return {
        "message": "Password changed successfully",
    }
