from uuid import UUID
from fastapi import HTTPException, status
from loguru import logger
from sqlmodel import select

from server.users.models import User
from server.database.core import SessionDep
from server.auth.security import security
from server.users.models import PasswordChange



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


    async def change_password(
        self,
        user_id: UUID,
        password_change: PasswordChange
    ):
        try:
            user = await self.get_user_by_id(user_id)

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            if not security.verify_password(password_change.current_password, user.password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            if password_change.new_password != password_change.new_password_confirm:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Passwords do not match",
                )
            
            user.password = security.get_password_hash(password_change.new_password)
            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"Successfully changed password for user ID: {user_id}")
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error during password change for user ID: {user_id}. Error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while changing the password.",
            )


