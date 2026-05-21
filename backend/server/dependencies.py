from typing import Annotated

import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException, status
from jwt.exceptions import InvalidTokenError
from sqlmodel import select

from server.database.core import SessionDep
from server.users.models import User
from server.config import settings


security = HTTPBearer()


async def get_current_user(
    session: SessionDep,
    authorization: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    token = authorization.credentials

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        email_address = payload.get("sub")
        if email_address is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    result = await session.execute(
        select(User).where(User.email_address == email_address)
    )
    user = result.scalars().first()
    if user is None:
        raise credentials_exception

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
