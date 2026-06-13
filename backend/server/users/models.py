from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime, Text


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    __tablename__ = "users"  # avoid reserved word "user" in PostgreSQL

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email_address: str = Field(index=True, unique=True)

    # NULL for Google-only users who have never set a local password.
    password: Optional[str] = Field(default=None)

    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )

    # ── Account lockout ───────────────────────────────────────────────────────
    # Architecture note:
    #   These live on the User row (not Redis) so they survive a cache restart.
    #   failed_attempts: incremented on each wrong password, reset on success.
    #   locked_until:    set to now + ACCOUNT_LOCK_MINUTES after N failures.
    #                    NULL means the account is not locked.
    failed_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    # ── Google OAuth ──────────────────────────────────────────────────────────
    # google_id: the "sub" claim from Google's ID token — globally unique per
    #   Google account. NULL for users who registered with email + password.
    # avatar_url: Google profile picture URL, updated on every OAuth login.
    google_id: Optional[str] = Field(default=None, index=True, unique=True)
    avatar_url: Optional[str] = Field(default=None)



class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    # Store hash of token, never the raw value
    token_hash: str = Field(index=True, unique=True)
    user_id: UUID = Field(foreign_key="users.id", index=True)
    # All tokens issued in the same login session share a family_id.
    # If a revoked token from this family is ever presented, the whole family
    # is revoked (reuse detection).
    family_id: UUID = Field(default_factory=uuid4, index=True)
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    is_revoked: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class OtpCode(SQLModel, table=True):
    __tablename__ = "otp_codes"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    # SHA-256 hash of the raw 6-digit code — never store plaintext
    code_hash: str = Field(index=True)
    user_id: UUID = Field(foreign_key="users.id", index=True)
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    # Incremented on every wrong guess; code is burned at OTP_MAX_ATTEMPTS
    attempts: int = Field(default=0)
    is_used: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class LoginAudit(SQLModel, table=True):
    """
    Append-only audit log of every login attempt.

    Architecture note — why a separate table?
      Audit logs should be immutable. You never UPDATE a login_audit row —
      you only INSERT. Keeping it separate from users also means you can
      archive/partition old rows without touching the users table, and you can
      grant read-only access to a security team without exposing password hashes.

    Useful queries:
      - All logins for a user in the last 7 days
      - All failed logins from a given IP
      - Impossible-travel detection (two logins from distant IPs within minutes)
    """
    __tablename__ = "login_audit"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    # NULL user_id = attempt for an email that doesn't exist in our DB
    user_id: Optional[UUID] = Field(default=None, foreign_key="users.id", index=True)
    ip_address: str = Field(index=True)
    success: bool
    # Human-readable reason for failures: "wrong_password", "account_locked", etc.
    failure_reason: Optional[str] = Field(default=None)
    # Device info (populated when available)
    device_fingerprint: Optional[str] = Field(default=None, index=True)
    os: Optional[str] = Field(default=None)
    browser: Optional[str] = Field(default=None)
    device_type: Optional[str] = Field(default=None)
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class KnownDevice(SQLModel, table=True):
    """
    One row per user+device fingerprint pair.

    Architecture note:
      This is an UPSERT table — if the fingerprint already exists for this
      user, we update last_seen. If it's new, we insert.
      This lets you answer: "Is this the first time this user has logged in
      from this device?" and optionally trigger a "new device" email alert.
    """
    __tablename__ = "known_devices"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="users.id", index=True)
    device_fingerprint: str = Field(index=True)
    # Human-readable device info
    os: str = Field(default="Unknown")
    browser: str = Field(default="Unknown")
    device_type: str = Field(default="Other")
    raw_user_agent: Optional[str] = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    first_seen: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    last_seen: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class UserResponse(SQLModel):
    id: UUID
    email_address: str
    avatar_url: Optional[str] = None
    has_google: bool = False  # True when google_id is set
