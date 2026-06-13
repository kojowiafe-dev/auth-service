from datetime import datetime, timezone, timedelta
from decimal import Decimal
from uuid import UUID, uuid4
from typing import Optional, Dict, Any, List
from fastapi import HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from server.wallet.models import Wallet, Transaction, LedgerEntry, WalletAuditLog


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WalletService:
    DAILY_LIMIT_GHS = Decimal("5000.00")
    VELOCITY_LIMIT_COUNT = 5  # max 5 transfers per minute
    VELOCITY_WINDOW_SECONDS = 60

    @staticmethod
    async def create_wallet(
        session: AsyncSession,
        user_id: UUID,
        currency: str
    ) -> Wallet:
        """
        Creates a new wallet for a user and registers an audit log.
        Enforces a single wallet per user per currency through DB unique constraint.
        """
        currency = currency.upper().strip()
        
        # Check if already exists to return gracefully rather than raising DB unique error
        stmt = select(Wallet).where(
            Wallet.user_id == user_id,
            Wallet.currency == currency
        )
        res = await session.execute(stmt)
        existing_wallet = res.scalar_one_or_none()
        if existing_wallet:
            return existing_wallet

        wallet = Wallet(
            user_id=user_id,
            currency=currency,
            is_active=True
        )
        session.add(wallet)
        await session.flush()  # gets the ID

        audit = WalletAuditLog(
            wallet_id=wallet.id,
            user_id=user_id,
            action="wallet_created",
            metadata_={"currency": currency}
        )
        session.add(audit)
        
        await session.commit()
        await session.refresh(wallet)
        logger.info(f"Created wallet {wallet.id} for user {user_id} in {currency}")
        return wallet

    @staticmethod
    async def get_wallet_by_id(
        session: AsyncSession,
        wallet_id: UUID
    ) -> Optional[Wallet]:
        return await session.get(Wallet, wallet_id)

    @staticmethod
    async def get_user_wallets(
        session: AsyncSession,
        user_id: UUID
    ) -> List[Wallet]:
        stmt = select(Wallet).where(Wallet.user_id == user_id)
        res = await session.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def get_balance(
        session: AsyncSession,
        wallet_id: UUID
    ) -> Decimal:
        """
        Derives the current wallet balance by summing all its ledger entries.
        """
        stmt = select(func.coalesce(func.sum(LedgerEntry.amount), 0)).where(
            LedgerEntry.wallet_id == wallet_id
        )
        res = await session.execute(stmt)
        return Decimal(res.scalar() or 0)

    @staticmethod
    async def transfer_money(
        session: AsyncSession,
        sender_user_id: UUID,
        idempotency_key: str,
        source_wallet_id: UUID,
        destination_wallet_id: UUID,
        amount: Decimal,
        currency: str,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        P2P transfer wrapper with Stripe-level idempotency and safety controls.
        """
        if amount <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Transfer amount must be greater than zero"
            )

        currency = currency.upper().strip()

        # 1. Handle Idempotency Key registration
        tx = await WalletService._get_or_create_transaction(session, idempotency_key, amount, currency, source_wallet_id, destination_wallet_id, description)
        
        if tx.status == "SUCCESS":
            return tx.response_payload
        elif tx.status == "FAILED":
            # If the stored failure payload is present, return it
            if tx.response_payload:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=tx.response_payload.get("detail", "Transaction failed")
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Transaction failed"
            )

        # If we got here, transaction status is PENDING.
        # Run transfer execution under row lock protection.
        try:
            response_data = await WalletService._execute_transfer_logic(
                session, sender_user_id, tx.id, source_wallet_id, destination_wallet_id, amount, currency
            )
            # Success! Update status and save payload
            tx.status = "SUCCESS"
            tx.response_payload = response_data
            session.add(tx)
            await session.commit()
            return response_data

        except HTTPException as he:
            # Expected business validation failure. Rollback business logic, mark TX as FAILED.
            await session.rollback()
            logger.warning(f"Business logic transfer failure: {he.detail}")
            
            # Start a clean transaction block to save the failed state
            tx.status = "FAILED"
            tx.response_payload = {"detail": he.detail, "status_code": he.status_code}
            session.add(tx)
            await session.commit()
            raise he
        except Exception as e:
            # Unexpected system error. Rollback business logic, mark TX as FAILED.
            await session.rollback()
            logger.error(f"Unexpected transaction system failure: {str(e)}")
            
            tx.status = "FAILED"
            tx.response_payload = {"detail": "Internal transaction failure", "status_code": 500}
            session.add(tx)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Transaction aborted due to system error"
            )

    @staticmethod
    async def _get_or_create_transaction(
        session: AsyncSession,
        idempotency_key: str,
        amount: Decimal,
        currency: str,
        source_id: UUID,
        destination_id: UUID,
        description: Optional[str]
    ) -> Transaction:
        """
        Attempts to register the idempotency key.
        Returns a Transaction object which can be in PENDING, SUCCESS, or FAILED state.
        """
        # 1. Query if it exists
        stmt = select(Transaction).where(Transaction.idempotency_key == idempotency_key)
        res = await session.execute(stmt)
        tx = res.scalar_one_or_none()
        if tx:
            if tx.status == "PENDING":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Transaction is already in progress"
                )
            return tx

        # 2. Try creating a new one
        try:
            tx = Transaction(
                idempotency_key=idempotency_key,
                amount=amount,
                currency=currency,
                source_wallet_id=source_id,
                destination_wallet_id=destination_id,
                status="PENDING",
                description=description
            )
            session.add(tx)
            await session.commit()
            await session.refresh(tx)
            return tx
        except IntegrityError:
            # In case of concurrent insert race condition, rollback and fetch the winning key row
            await session.rollback()
            stmt = select(Transaction).where(Transaction.idempotency_key == idempotency_key)
            res = await session.execute(stmt)
            tx = res.scalar_one_or_none()
            if tx:
                if tx.status == "PENDING":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Transaction is already in progress"
                    )
                return tx
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Idempotency registration conflict"
            )

    @staticmethod
    async def _execute_transfer_logic(
        session: AsyncSession,
        sender_user_id: UUID,
        transaction_id: UUID,
        source_id: UUID,
        destination_id: UUID,
        amount: Decimal,
        currency: str
    ) -> Dict[str, Any]:
        """
        Core transfer business logic. Runs within a database transaction block.
        Loads wallets using row-level locking (SELECT FOR UPDATE) to prevent concurrency races.
        """
        if source_id == destination_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Source and destination wallets must be different"
            )

        # Deterministic locking order to prevent deadlocks (lock smaller UUID first)
        locked_ids = sorted([source_id, destination_id])
        
        # Lock rows in DB
        stmt = select(Wallet).where(Wallet.id.in_(locked_ids)).with_for_update()
        res = await session.execute(stmt)
        wallets = {w.id: w for w in res.scalars().all()}

        source_wallet = wallets.get(source_id)
        destination_wallet = wallets.get(destination_id)

        # 2. Perform wallet checks
        if not source_wallet:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Source wallet not found"
            )
        if not destination_wallet:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Destination wallet not found"
            )

        # Verify wallet ownership of the sender
        if source_wallet.user_id != sender_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not own the source wallet"
            )

        if not source_wallet.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Source wallet is inactive"
            )
        if not destination_wallet.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Destination wallet is inactive"
            )

        # Currency checks
        if source_wallet.currency != currency:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Source wallet currency ({source_wallet.currency}) does not match transaction currency ({currency})"
            )
        if destination_wallet.currency != currency:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Destination wallet currency ({destination_wallet.currency}) does not match transaction currency ({currency})"
            )

        # 3. Daily Limit Verification
        today_start = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        # Find sum of debits (negative ledger entries) today
        stmt_daily = select(func.coalesce(func.sum(LedgerEntry.amount), 0)).where(
            LedgerEntry.wallet_id == source_id,
            LedgerEntry.amount < 0,
            LedgerEntry.created_at >= today_start
        )
        res_daily = await session.execute(stmt_daily)
        todays_debit = abs(res_daily.scalar() or Decimal(0))

        if todays_debit + amount > WalletService.DAILY_LIMIT_GHS:
            # Log limit exceeded audit
            audit = WalletAuditLog(
                wallet_id=source_id,
                user_id=sender_user_id,
                action="limit_exceeded",
                metadata_={
                    "amount": str(amount),
                    "todays_debit": str(todays_debit),
                    "limit": str(WalletService.DAILY_LIMIT_GHS)
                }
            )
            session.add(audit)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Daily transfer limit of {WalletService.DAILY_LIMIT_GHS} {currency} exceeded"
            )

        # 4. Velocity Check
        window_start = _utcnow() - timedelta(seconds=WalletService.VELOCITY_WINDOW_SECONDS)
        stmt_velocity = select(func.count(Transaction.id)).where(
            Transaction.source_wallet_id == source_id,
            Transaction.status == "SUCCESS",
            Transaction.created_at >= window_start
        )
        res_velocity = await session.execute(stmt_velocity)
        recent_count = res_velocity.scalar() or 0

        if recent_count >= WalletService.VELOCITY_LIMIT_COUNT:
            audit = WalletAuditLog(
                wallet_id=source_id,
                user_id=sender_user_id,
                action="velocity_flag",
                metadata_={
                    "count": recent_count,
                    "window_seconds": WalletService.VELOCITY_WINDOW_SECONDS
                }
            )
            session.add(audit)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Velocity limit exceeded. Too many transfers in a short period."
            )

        # 5. Check Sender Balance
        sender_balance = await WalletService.get_balance(session, source_id)
        if sender_balance < amount:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Insufficient funds"
            )

        # 6. Perform Double-Entry Ledger Inserts
        debit_entry = LedgerEntry(
            transaction_id=transaction_id,
            wallet_id=source_id,
            amount=-amount
        )
        credit_entry = LedgerEntry(
            transaction_id=transaction_id,
            wallet_id=destination_id,
            amount=amount
        )

        session.add(debit_entry)
        session.add(credit_entry)

        # 7. Audit log the transfer
        audit_transfer = WalletAuditLog(
            wallet_id=source_id,
            user_id=sender_user_id,
            action="transfer_completed",
            metadata_={
                "transaction_id": str(transaction_id),
                "destination_wallet_id": str(destination_id),
                "amount": str(amount),
                "currency": currency
            }
        )
        session.add(audit_transfer)

        # Flush changes to DB to verify constraints before committing outside
        await session.flush()

        return {
            "transaction_id": str(transaction_id),
            "source_wallet_id": str(source_id),
            "destination_wallet_id": str(destination_id),
            "amount": str(amount),
            "currency": currency,
            "status": "SUCCESS",
            "sender_balance": str(sender_balance - amount)
        }

    @staticmethod
    async def deposit_funds_system(
        session: AsyncSession,
        wallet_id: UUID,
        amount: Decimal,
        currency: str,
        description: str = "System Deposit"
    ) -> Transaction:
        """
        Helper method to deposit funds into a wallet directly (e.g. system funding or deposit simulate).
        Creates a Transaction and a single positive ledger entry.
        """
        if amount <= 0:
            raise HTTPException(status_code=400, detail="Deposit amount must be positive")
        
        currency = currency.upper().strip()
        wallet = await session.get(Wallet, wallet_id)
        if not wallet:
            raise HTTPException(status_code=404, detail="Wallet not found")
        if wallet.currency != currency:
            raise HTTPException(status_code=400, detail="Currency mismatch")
        if not wallet.is_active:
            raise HTTPException(status_code=400, detail="Wallet is inactive")

        # Create system transaction
        tx = Transaction(
            idempotency_key=f"system_deposit_{uuid4()}",
            amount=amount,
            currency=currency,
            destination_wallet_id=wallet_id,
            status="SUCCESS",
            description=description
        )
        session.add(tx)
        await session.flush()

        # Credit the user
        credit = LedgerEntry(
            transaction_id=tx.id,
            wallet_id=wallet_id,
            amount=amount
        )
        session.add(credit)

        audit = WalletAuditLog(
            wallet_id=wallet_id,
            user_id=wallet.user_id,
            action="system_deposit",
            metadata_={"amount": str(amount), "currency": currency}
        )
        session.add(audit)
        
        await session.commit()
        await session.refresh(tx)
        return tx

    @staticmethod
    async def get_transaction_history(
        session: AsyncSession,
        wallet_id: UUID
    ) -> List[Transaction]:
        """
        Returns all transactions where the wallet is either source or destination.
        """
        stmt = select(Transaction).where(
            (Transaction.source_wallet_id == wallet_id) |
            (Transaction.destination_wallet_id == wallet_id)
        ).order_by(Transaction.created_at.desc())
        res = await session.execute(stmt)
        return list(res.scalars().all())
