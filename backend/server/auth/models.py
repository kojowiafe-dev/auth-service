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
    access_token: str
    token_type: str
    role: str

    model_config = ConfigDict(from_attributes=True)