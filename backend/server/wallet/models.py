from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from decimal import Decimal
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime, Numeric, JSON, UniqueConstraint


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Wallet(SQLModel, table=True):
    __tablename__ = "wallets"
    __table_args__ = (
        UniqueConstraint("user_id", "currency", name="uq_user_wallet_currency"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="users.id", index=True)
    currency: str = Field(index=True, max_length=3)
    is_active: bool = Field(default=True)
    
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class Transaction(SQLModel, table=True):
    __tablename__ = "transactions"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    idempotency_key: str = Field(index=True, unique=True, max_length=255)
    amount: Decimal = Field(
        sa_column=Column(Numeric(18, 4), nullable=False)
    )
    currency: str = Field(max_length=3)
    source_wallet_id: Optional[UUID] = Field(
        default=None, foreign_key="wallets.id", nullable=True, index=True
    )
    destination_wallet_id: Optional[UUID] = Field(
        default=None, foreign_key="wallets.id", nullable=True, index=True
    )
    status: str = Field(default="PENDING", index=True)  # PENDING, SUCCESS, FAILED
    description: Optional[str] = Field(default=None, max_length=255)
    
    # Store dynamic response body (e.g. status code and response data) for idempotency replays
    response_payload: Optional[Dict[str, Any]] = Field(
        default=None,
        sa_column=Column(JSON, nullable=True)
    )
    
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class LedgerEntry(SQLModel, table=True):
    __tablename__ = "ledger_entries"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    transaction_id: UUID = Field(foreign_key="transactions.id", index=True)
    wallet_id: UUID = Field(foreign_key="wallets.id", index=True)
    
    # Signed change: negative for debit (outflow), positive for credit (inflow)
    amount: Decimal = Field(
        sa_column=Column(Numeric(18, 4), nullable=False)
    )
    
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class WalletAuditLog(SQLModel, table=True):
    __tablename__ = "wallet_audit_logs"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    wallet_id: Optional[UUID] = Field(
        default=None, foreign_key="wallets.id", index=True, nullable=True
    )
    user_id: Optional[UUID] = Field(
        default=None, foreign_key="users.id", index=True, nullable=True
    )
    action: str = Field(index=True, max_length=100)  # wallet_created, limit_exceeded, suspicious_activity, etc.
    
    metadata_: Optional[Dict[str, Any]] = Field(
        default=None,
        sa_column=Column("metadata", JSON, nullable=True)
    )
    
    created_at: datetime = Field(
        default_factory=_utcnow,
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
