from server.database.core import SessionDep
from server.models.auth import User
from fastapi import HTTPException, status, HTTPException
from server.models.auth import AuthBase


class AuthService:
    def __init__(self, session: SessionDep):
        self.session = session

    async def register(
        self, 
        request: AuthBase
    ):
        try:
            # check if user already exists
            result = await self.session.execute(
                select(User).where(User.phone_number == request.phone_number)
            )
            existing_user = result.scalars().first()

            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists"
                )

            user = User(
                phone_number=request.phone_number,
                password=get_password_hash(request.password),
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
        request: AuthBase,
    ):
        # Find user by phone number
        existing_user = await self.session.execute(
            select(User).where(User.phone_number == request.phone_number)
        )
        existing_user = existing_user.scalars().first()

        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

        if not verify_password(request.password, existing_user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password"
            )

        access_token = token_access.create_access_token(
            data={"sub": existing_user.phone_number, "role": existing_user.role}
        )

        existing_user.last_seen = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).replace(tzinfo=None)
        await self.session.commit()
        await self.session.refresh(existing_user)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": existing_user.role
        }