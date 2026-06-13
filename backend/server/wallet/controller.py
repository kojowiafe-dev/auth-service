from datetime import datetime
from decimal import Decimal
from uuid import UUID
from typing import Optional, List
from fastapi import APIRouter, status, Header, HTTPException
from pydantic import BaseModel, Field
from loguru import logger

from server.database.core import SessionDep
from server.dependencies import CurrentUser
from server.wallet.service import WalletService

router = APIRouter(
    prefix="/wallets",
    tags=["Wallets"]
)


# ── Schemas ──────────────────────────────────────────────────────────────────

class WalletCreate(BaseModel):
    currency: str = Field(..., min_length=3, max_length=3, description="3-letter currency ISO code")


class WalletResponse(BaseModel):
    id: UUID
    user_id: UUID
    currency: str
    balance: Decimal
    is_active: bool
    created_at: datetime


class TransferRequest(BaseModel):
    source_wallet_id: UUID
    destination_wallet_id: UUID
    amount: Decimal = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    description: Optional[str] = None


class DepositRequest(BaseModel):
    amount: Decimal = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    description: Optional[str] = "System Deposit"


class TransactionResponse(BaseModel):
    id: UUID
    amount: Decimal
    currency: str
    source_wallet_id: Optional[UUID]
    destination_wallet_id: Optional[UUID]
    status: str
    description: Optional[str]
    created_at: datetime


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=WalletResponse,
    status_code=status.HTTP_201_CREATED
)
async def create_wallet(
    request: WalletCreate,
    session: SessionDep,
    user: CurrentUser
):
    """
    Create a new wallet in the specified currency for the logged-in user.
    """
    logger.info(f"Creating wallet for user {user.id} in currency {request.currency}")
    wallet = await WalletService.create_wallet(
        session=session,
        user_id=user.id,
        currency=request.currency
    )
    balance = await WalletService.get_balance(session, wallet.id)
    return WalletResponse(
        id=wallet.id,
        user_id=wallet.user_id,
        currency=wallet.currency,
        balance=balance,
        is_active=wallet.is_active,
        created_at=wallet.created_at
    )


@router.get(
    "/me",
    response_model=List[WalletResponse],
    status_code=status.HTTP_200_OK
)
async def get_my_wallets(
    session: SessionDep,
    user: CurrentUser
):
    """
    Retrieve all wallets owned by the logged-in user with their derived balances.
    """
    logger.info(f"Fetching wallets for user {user.id}")
    wallets = await WalletService.get_user_wallets(session, user.id)
    
    response = []
    for w in wallets:
        balance = await WalletService.get_balance(session, w.id)
        response.append(
            WalletResponse(
                id=w.id,
                user_id=w.user_id,
                currency=w.currency,
                balance=balance,
                is_active=w.is_active,
                created_at=w.created_at
            )
        )
    return response


@router.post(
    "/transfer",
    status_code=status.HTTP_200_OK
)
async def transfer_funds(
    request: TransferRequest,
    session: SessionDep,
    user: CurrentUser,
    idempotency_key: str = Header(..., alias="Idempotency-Key")
):
    """
    Transfer funds between two wallets. Requires Idempotency-Key header.
    """
    logger.info(f"Transfer request from user {user.id} using key {idempotency_key}")
    # Remove whitespace or empty keys
    clean_key = idempotency_key.strip()
    if not clean_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Idempotency-Key header cannot be empty"
        )
        
    result = await WalletService.transfer_money(
        session=session,
        sender_user_id=user.id,
        idempotency_key=clean_key,
        source_wallet_id=request.source_wallet_id,
        destination_wallet_id=request.destination_wallet_id,
        amount=request.amount,
        currency=request.currency,
        description=request.description
    )
    return result


@router.post(
    "/{wallet_id}/deposit",
    status_code=status.HTTP_200_OK
)
async def deposit_funds(
    wallet_id: UUID,
    request: DepositRequest,
    session: SessionDep,
    user: CurrentUser
):
    """
    Deposit funds into a wallet. (For testing / simulated external deposits).
    """
    logger.info(f"Depositing funds to wallet {wallet_id} for user {user.id}")
    wallet = await WalletService.get_wallet_by_id(session, wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    if wallet.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not own this wallet"
        )
        
    tx = await WalletService.deposit_funds_system(
        session=session,
        wallet_id=wallet_id,
        amount=request.amount,
        currency=request.currency,
        description=request.description
    )
    return {
        "status": "SUCCESS",
        "transaction_id": str(tx.id),
        "amount": str(request.amount),
        "currency": request.currency
    }


@router.get(
    "/{wallet_id}/transactions",
    response_model=List[TransactionResponse],
    status_code=status.HTTP_200_OK
)
async def get_wallet_transactions(
    wallet_id: UUID,
    session: SessionDep,
    user: CurrentUser
):
    """
    Retrieve transaction history for a specific wallet.
    """
    logger.info(f"Fetching transactions for wallet {wallet_id} for user {user.id}")
    wallet = await WalletService.get_wallet_by_id(session, wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found"
        )
    if wallet.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not own this wallet"
        )
        
    transactions = await WalletService.get_transaction_history(session, wallet_id)
    return transactions
