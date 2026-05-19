from pydantic import EmailStr
from uuid import UUID, uuid4
from datetime import datetime
from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email_address: str = Field(index=True, unique=True)
    password: str
    created_at: datetime = Field(default=datetime.now())
    updated_at: datetime = Field(default=datetime.now())


class UserResponse(SQLModel):
    id: UUID
    email: EmailStr


class PasswordChange(SQLModel):
    current_password: str
    new_password: str
    new_password_confirm: str
