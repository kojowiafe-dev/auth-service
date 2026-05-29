from fastapi import HTTPException, status
from loguru import logger
from sqlmodel import select
from sqlalchemy.exc import IntegrityError
from uuid import UUID

from server.users.models import User
from server.auth.security import security
from server.auth.token_access import token_access
from server.database.core import SessionDep
from server.auth.otp import send_email
from server.auth.models import PasswordChange, OtpRequest


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


    async def forgot_password(self, email_address: str):
        existing_user = await self.session.execute(
            select(User).where(User.email_address == email_address)
        )
        existing_user = existing_user.scalars().first()

        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        send_email(existing_user.email_address, existing_user.name)

        if not send_email:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during OTP sending.",
            )
        if send_email:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "message": "OTP sent successfully",
                    "otp": otp
                },
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "message": "Email not sent"
                },
            )


    async def authenticate_request(self, request: OtpRequest):
        try:
            user = await self.session.execute(
                select(User).where(User.email_address == request.email_address)
            )
            user = user.scalars().first()

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if not security.verify_password(request.otp, user.otp):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect OTP",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            access_token = token_access.create_access_token(
                data={"sub": user.email_address}
            )

            return {
                "access_token": access_token,
                "token_type": "bearer",
            }
        except Exception as e:
            logger.error(f"Error authenticating request: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while authenticating the request.",
            )


    async def change_password(
        self,
        password_change: PasswordChange
    ):
        try:
            # authenticate the request
            current_user = await self.authenticate_request(password_change)

            if not security.verify_password(password_change.current_password, current_user.password):
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

            current_user.password = security.get_password_hash(password_change.new_password)
            self.session.add(current_user)
            await self.session.commit()
            await self.session.refresh(current_user)
            logger.info(f"Successfully changed password for user ID: {current_user.id}")
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error during password change for user ID: {current_user.id}. Error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while changing the password.",
            )



auth_service = AuthService(session=SessionDep)