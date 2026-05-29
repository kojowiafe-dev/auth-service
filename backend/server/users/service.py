from uuid import UUID
from fastapi import HTTPException, status
from loguru import logger
from sqlmodel import select

from server.users.models import User
from server.database.core import SessionDep



class UserService:
    def __init__(self, session: SessionDep):
        self.session = session


    async def get_users(
        self
    ):
        # try:
        result = await self.session.execute(select(User))
        return result.scalars().all()
        # except Exception as e:
        #     logger.error(f"Error getting users: {e}")
        #     raise HTTPException(
        #         status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        #         detail="An error occurred while fetching users.",
        # )



    async def get_user_by_id(
        self,
        user_id: UUID
    ):
        try:
            result = await self.session.execute(
                select(User).where(User.id == user_id)
            )
            return result.scalars().first()
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while fetching user.",
            )