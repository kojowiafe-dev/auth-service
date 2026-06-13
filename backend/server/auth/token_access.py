import jwt
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from jose import JWTError
from dotenv import load_dotenv
import os
from uuid import UUID
from fastapi import HTTPException, status

load_dotenv()


class TokenManager:
    def __init__(self):
        self.secret_key = os.getenv("SECRET_KEY")
        self.algorithm = os.getenv("ALGORITHM")
        self.access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
        self.refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    # ------------------------------------------------------------------ #
    #  Access tokens (JWT)                                                 #
    # ------------------------------------------------------------------ #

    def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def decode_access_token(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            email_address = payload.get("sub")
            if email_address is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )
            return email_address
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    # ------------------------------------------------------------------ #
    #  Refresh tokens (opaque random token, hashed for storage)           #
    # ------------------------------------------------------------------ #

    def create_refresh_token(self) -> tuple[str, str, datetime]:
        """
        Returns (raw_token, token_hash, expires_at).
        Only the raw token is sent to the client; only the hash is stored in DB.
        """
        raw = secrets.token_urlsafe(64)
        token_hash = self._hash_token(raw)
        expires_at = datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days)
        return raw, token_hash, expires_at

    @staticmethod
    def _hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()


token_access = TokenManager()