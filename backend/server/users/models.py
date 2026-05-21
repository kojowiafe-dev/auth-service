from uuid import UUID, uuid4
from datetime import datetime
from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    __tablename__ = "users"  # avoid reserved word "user" in PostgreSQL

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email_address: str = Field(index=True, unique=True)
    password: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class UserResponse(SQLModel):
    id: UUID
    email_address: str



class PasswordChange(SQLModel):
    current_password: str
    new_password: str
    new_password_confirm: str
