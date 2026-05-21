from fastapi import HTTPException, status
from loguru import logger
from sqlmodel import select
from sqlalchemy.exc import IntegrityError

from server.users.models import User
from server.auth.security import security
from server.auth.token_access import token_access
from server.database.core import SessionDep



class AuthService:
    def __init__(self, session: SessionDep):
        self.session = session

    async def register(
        self, 
        request
    ):
        try:
            result = await self.session.execute(
                select(User).where(User.email_address == request.email_address)
            )
            existing_user = result.scalars().first()

            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists"
                )

            user = User(
                email_address=request.email_address,
                password=security.get_password_hash(request.password),
            )

            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)

            return user

        except HTTPException:
            raise

        except IntegrityError:
            await self.session.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists"
            )

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Registration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during registration."
            )


    async def login(
        self,
        request,
    ):
        existing_user = await self.session.execute(
            select(User).where(User.email_address == request.email_address)
        )
        existing_user = existing_user.scalars().first()

        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not security.verify_password(request.password, existing_user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token = token_access.create_access_token(
            data={"sub": existing_user.email_address}
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
        }



auth_service = AuthService