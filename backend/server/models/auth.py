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
    username: str = Field(index=True, unique=True)
    email: str = Field(index=True, unique=True)
    password: str
    created_at: datetime = Field(default=datetime.now())
    updated_at: datetime = Field(default=datetime.now())


class AuthBase(SQLModel):
    phone_number: str
    password: str   


class TokenData(SQLModel):
    username: Optional[str] = None
    
    def get_username(self) -> str | None:
        if self.username:
            return self.username
        return None


class Token(SQLModel):
    access_token: str
    token_type: str
    role: str

    model_config = ConfigDict(from_attributes=True)