from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum
from pydantic import ConfigDict


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email_address: str = Field(index=True, unique=True)
    password: str
    created_at: datetime = Field(default=datetime.now())
    updated_at: datetime = Field(default=datetime.now())


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
    access_token: str
    token_type: str
    role: str

    model_config = ConfigDict(from_attributes=True)