from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException, status
from loguru import logger
from jose import jwt, JWTError
from sqlmodel import select

from server.database.core import SessionDep
from server.auth.service import auth_service
from server.users.models import User
from server.config import settings


security = HTTPBearer()

async def get_current_user(
    session: SessionDep,
    authorization: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    token = authorization.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No token provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        email_address = payload.get("sub")
        if email_address is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = await session.execute(
        select(User).where(User.email_address == email_address)
    )
    user = user.scalars().first()
    if user is None:
        raise credentials_exception
    
    return user