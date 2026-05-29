from fastapi import APIRouter, status
from loguru import logger

from server.users.models import UserResponse
from server.users.service import UserService
from server.dependencies import CurrentUser
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
async def get_current_user_route(user: CurrentUser):
    logger.info(f"Getting current user: {user.email_address}")
    return {
        "id": user.id,
        "email_address": user.email_address,
    }
