from sqlmodel import SQLModel
from typing import Optional
from pydantic import ConfigDict


class AuthBase(SQLModel):
    email_address: str
    password: str


class TokenData(SQLModel):
    email_address: Optional[str] = None

    def get_email_address(self) -> str | None:
        if self.email_address:
            return self.email_address
        return None


class Token(SQLModel):
    """Returned to the client on login or token refresh."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class RefreshRequest(SQLModel):
    """Body for POST /auth/refresh."""
    refresh_token: str


class LogoutRequest(SQLModel):
    """Body for POST /auth/logout."""
    refresh_token: str


class PasswordChange(SQLModel):
    access_token: str
    current_password: str
    new_password: str
    new_password_confirm: str


class OtpRequest(SQLModel):
    email_address: str
    otp: str