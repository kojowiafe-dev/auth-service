from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import HTTPException, status
from loguru import logger
from sqlmodel import select
from sqlalchemy.exc import IntegrityError
from uuid import UUID

from server.users.models import User, RefreshToken, OtpCode, LoginAudit, KnownDevice
from server.auth.security import security
from server.auth.token_access import token_access
from server.database.core import SessionDep
from server.auth.otp import generate_otp, send_otp_email
from server.auth.models import PasswordChange, OtpRequest, RefreshRequest, LogoutRequest
from server.auth.device import parse_user_agent, fingerprint_device
from server.config import settings


class AuthService:
    def __init__(self, session: SessionDep):
        self.session = session

    async def register(self, request):
        try:
            result = await self.session.execute(
                select(User).where(User.email_address == request.email_address)
            )
            existing_user = result.scalars().first()

            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User already exists",
                )

            user = User(
                email_address=request.email_address,
                password=security.get_password_hash(request.password),
            )

            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)

            return user

        except HTTPException:
            raise

        except IntegrityError:
            await self.session.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists",
            )

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Registration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during registration.",
            )



    async def login(self, request, ip_address: str = "unknown", user_agent: str = ""):
        """
        Authenticate a user and return a token pair.

        Security layers applied (in order):
          1. Account lockout check  — reject if locked_until is in the future
          2. Password verification  — increment failed_attempts on failure
          3. Device fingerprinting  — derive a stable ID from IP + UA
          4. Audit logging          — write a LoginAudit row regardless of outcome
          5. Device upsert          — record / update KnownDevice on success
        """
        # ── Parse device info up-front (used in both success and failure paths) ──
        device_info = parse_user_agent(user_agent)
        fingerprint = fingerprint_device(ip_address, user_agent)

        # ── Look up the user ──────────────────────────────────────────────────
        result = await self.session.execute(
            select(User).where(User.email_address == request.email_address)
        )
        user = result.scalars().first()

        if not user:
            # Log the attempt even for unknown emails (without a user_id)
            # so you can detect email-enumeration / credential-stuffing campaigns.
            await self._write_audit(
                user_id=None,
                ip_address=ip_address,
                success=False,
                failure_reason="user_not_found",
                fingerprint=fingerprint,
                device_info=device_info,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # ── Step 1: Account lockout check ─────────────────────────────────────
        # Architecture note:
        #   locked_until is stored in Postgres (not Redis) so it survives a
        #   cache restart. We compare it against UTC now.
        if user.locked_until is not None:
            lock_time = user.locked_until
            if lock_time.tzinfo is None:
                lock_time = lock_time.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) < lock_time:
                wait_seconds = int((lock_time - datetime.now(timezone.utc)).total_seconds())
                await self._write_audit(
                    user_id=user.id,
                    ip_address=ip_address,
                    success=False,
                    failure_reason="account_locked",
                    fingerprint=fingerprint,
                    device_info=device_info,
                )
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=(
                        f"Account is temporarily locked due to too many failed attempts. "
                        f"Try again in {wait_seconds} seconds."
                    ),
                )
            else:
                # Lock has expired — clear it
                user.locked_until = None
                user.failed_attempts = 0

        # ── Step 2: Password verification ─────────────────────────────────────
        if not security.verify_password(request.password, user.password):
            user.failed_attempts += 1
            failure_reason = "wrong_password"

            # Architecture note — account lockout trigger:
            #   After ACCOUNT_LOCK_ATTEMPTS consecutive wrong passwords we set
            #   locked_until. The counter resets to 0 on a successful login.
            if user.failed_attempts >= settings.ACCOUNT_LOCK_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=settings.ACCOUNT_LOCK_MINUTES
                )
                failure_reason = "account_locked_now"
                logger.warning(
                    f"Account locked for {user.email_address} after "
                    f"{user.failed_attempts} failed attempts from {ip_address}"
                )

            user_id = user.id
            await self.session.commit()
            await self._write_audit(
                user_id=user_id,
                ip_address=ip_address,
                success=False,
                failure_reason=failure_reason,
                fingerprint=fingerprint,
                device_info=device_info,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # ── Step 3: Successful auth — reset lockout counters ──────────────────
        user.failed_attempts = 0
        user.locked_until = None

        # ── Step 4: Issue tokens ──────────────────────────────────────────────
        email = user.email_address  # read before commit expires the object
        user_id = user.id

        access_token = token_access.create_access_token(data={"sub": email})
        raw_refresh, refresh_hash, expires_at = token_access.create_refresh_token()

        refresh_token_record = RefreshToken(
            token_hash=refresh_hash,
            user_id=user_id,
            expires_at=expires_at,
        )
        self.session.add(refresh_token_record)
        logger.info(f"User logged in: {email} from {ip_address} [{device_info['device_type']}]")
        await self.session.commit()

        # ── Step 5: Write audit log + upsert known device ─────────────────────
        # Both are fire-and-forget after the main commit; errors here should
        # NOT roll back the successful login.
        try:
            await self._write_audit(
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                fingerprint=fingerprint,
                device_info=device_info,
            )
            await self._upsert_device(
                user_id=user_id,
                fingerprint=fingerprint,
                device_info=device_info,
                user_agent=user_agent,
            )
        except Exception as e:
            logger.error(f"Audit/device logging failed (non-fatal): {e}")

        return {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
        }

    async def google_login(
        self,
        google_info: dict,
        ip_address: str = "unknown",
        user_agent: str = "",
    ):
        """
        Find-or-create a User from Google OAuth profile data, then issue tokens.

        Auto-linking strategy (approved):
          - Look up by google_id first (returning user who used Google before).
          - If not found, look up by email address.
              · Found by email → link: attach google_id + avatar_url to the
                existing account (works even if they registered with a password).
              · Not found at all → create a new User with no local password.
          - Issue our own access + refresh token pair (identical to normal login).

        Args:
            google_info: dict returned by get_google_user_info(), containing
                         at least {id, email, picture}.
            ip_address:  client IP for audit + device fingerprinting.
            user_agent:  raw UA string for device fingerprinting.
        """
        google_id  = google_info["id"]
        email      = google_info["email"]
        avatar_url = google_info.get("picture")

        device_info = parse_user_agent(user_agent)
        fingerprint = fingerprint_device(ip_address, user_agent)

        # ── Step 1: find by google_id (fast path for returning users) ──────────
        result = await self.session.execute(
            select(User).where(User.google_id == google_id)
        )
        user = result.scalars().first()

        if not user:
            # ── Step 2: find by email — auto-link if found ─────────────────────
            result = await self.session.execute(
                select(User).where(User.email_address == email)
            )
            user = result.scalars().first()

            if user:
                # Existing email/password account → attach Google identity
                user.google_id  = google_id
                user.avatar_url = avatar_url
                await self.session.commit()
                await self.session.refresh(user)  # re-load attrs expired by commit
                logger.info(
                    f"Google account auto-linked to existing user: {email}"
                )
            else:
                # ── Step 3: brand-new user via Google ──────────────────────────
                user = User(
                    email_address=email,
                    password=None,       # no local password for OAuth users
                    google_id=google_id,
                    avatar_url=avatar_url,
                )
                self.session.add(user)
                await self.session.commit()
                await self.session.refresh(user)
                logger.info(f"New user created via Google OAuth: {email}")
        else:
            # Returning Google user — refresh avatar in case they changed it
            if user.avatar_url != avatar_url:
                user.avatar_url = avatar_url
                await self.session.commit()
                await self.session.refresh(user)  # re-load attrs expired by commit

        # ── Issue our own token pair ──────────────────────────────────────────
        user_id      = user.id
        access_token = token_access.create_access_token(data={"sub": email})
        raw_refresh, refresh_hash, expires_at = token_access.create_refresh_token()

        refresh_record = RefreshToken(
            token_hash=refresh_hash,
            user_id=user_id,
            expires_at=expires_at,
        )
        self.session.add(refresh_record)
        await self.session.commit()

        logger.info(f"Google login successful: {email} from {ip_address}")

        # ── Audit + device (non-fatal) ────────────────────────────────────────
        try:
            await self._write_audit(
                user_id=user_id,
                ip_address=ip_address,
                success=True,
                fingerprint=fingerprint,
                device_info=device_info,
            )
            await self._upsert_device(
                user_id=user_id,
                fingerprint=fingerprint,
                device_info=device_info,
                user_agent=user_agent,
            )
        except Exception as e:
            logger.error(f"Audit/device logging failed (non-fatal): {e}")

        return {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _write_audit(
        self,
        ip_address: str,
        success: bool,
        user_id: Optional[UUID] = None,
        failure_reason: Optional[str] = None,
        fingerprint: Optional[str] = None,
        device_info: Optional[dict] = None,
    ) -> None:
        """
        Append a row to login_audit.

        Architecture note — why always write, success or failure?
          An attacker probing your system generates failure rows, making it
          easy to query: "show me all IPs that failed more than 20 times in
          the last hour" — that's your threat list.
          Successful rows let you build a login history for users
          ("last seen from Berlin on Monday").
        """
        info = device_info or {}
        audit = LoginAudit(
            user_id=user_id,
            ip_address=ip_address,
            success=success,
            failure_reason=failure_reason,
            device_fingerprint=fingerprint,
            os=info.get("os"),
            browser=info.get("browser"),
            device_type=info.get("device_type"),
        )
        self.session.add(audit)
        await self.session.commit()

    async def _upsert_device(
        self,
        user_id: UUID,
        fingerprint: str,
        device_info: dict,
        user_agent: str,
    ) -> None:
        """
        Insert or update a KnownDevice row.

        Architecture note — UPSERT pattern:
          We first try to SELECT the device. If found, update last_seen.
          If not found, INSERT a new row.
          SQLModel/SQLAlchemy don't have a database-agnostic ON CONFLICT
          clause for async, so we do it in two steps inside the same session.
        """
        result = await self.session.execute(
            select(KnownDevice).where(
                KnownDevice.user_id == user_id,
                KnownDevice.device_fingerprint == fingerprint,
            )
        )
        device = result.scalars().first()

        now = datetime.now(timezone.utc)
        if device:
            device.last_seen = now
            # Update browser/OS in case the user upgraded their browser
            device.os = device_info.get("os", device.os)
            device.browser = device_info.get("browser", device.browser)
        else:
            device = KnownDevice(
                user_id=user_id,
                device_fingerprint=fingerprint,
                os=device_info.get("os", "Unknown"),
                browser=device_info.get("browser", "Unknown"),
                device_type=device_info.get("device_type", "Other"),
                raw_user_agent=user_agent[:512] if user_agent else None,
                first_seen=now,
                last_seen=now,
            )
            self.session.add(device)
            logger.info(
                f"New device registered for user {user_id}: "
                f"{device_info.get('browser')} on {device_info.get('os')}"
            )

        await self.session.commit()

    async def forgot_password(self, request):
        result = await self.session.execute(
            select(User).where(User.email_address == request.email_address)
        )
        user = result.scalars().first()

        if not user:
            # Return generic success to avoid user enumeration
            logger.info(f"Forgot-password requested for unknown email: {request.email_address}")
            return {"message": "If that email exists, an OTP has been sent."}

        # Invalidate any previous unused OTPs for this user
        existing_result = await self.session.execute(
            select(OtpCode).where(
                OtpCode.user_id == user.id,
                OtpCode.is_used == False,  # noqa: E712
            )
        )
        for old_otp in existing_result.scalars().all():
            old_otp.is_used = True

        # Generate new OTP and persist only the hash
        raw_otp, code_hash = generate_otp()
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=int(settings.RESET_TOKEN_EXPIRE_MINUTES)
        )

        otp_record = OtpCode(
            code_hash=code_hash,
            user_id=user.id,
            expires_at=expires_at,
        )
        self.session.add(otp_record)
        await self.session.commit()

        # Send email (raises HTTPException on failure)
        send_otp_email(user.email_address, user.email_address, raw_otp)

        logger.info(f"OTP sent to {user.email_address}, expires at {expires_at}")
        return {"message": "If that email exists, an OTP has been sent."}

    async def authenticate_request(self, request: OtpRequest):
        import hashlib

        result = await self.session.execute(
            select(User).where(User.email_address == request.email_address)
        )
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Find the most recent active OTP for this user
        otp_result = await self.session.execute(
            select(OtpCode).where(
                OtpCode.user_id == user.id,
                OtpCode.is_used == False,  # noqa: E712
            ).order_by(OtpCode.created_at.desc())
        )
        otp_record = otp_result.scalars().first()

        if not otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active OTP found. Please request a new one.",
            )

        # Expiry check
        now = datetime.now(timezone.utc)
        expires_at = otp_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            otp_record.is_used = True
            await self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has expired. Please request a new one.",
            )

        # Attempt limit check (before verifying, to prevent timing oracle)
        if otp_record.attempts >= settings.OTP_MAX_ATTEMPTS:
            otp_record.is_used = True
            await self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Maximum of {settings.OTP_MAX_ATTEMPTS} attempts reached. "
                    "Please request a new OTP."
                ),
            )

        # Verify code
        submitted_hash = hashlib.sha256(request.otp.encode()).hexdigest()
        if submitted_hash != otp_record.code_hash:
            otp_record.attempts += 1
            remaining = settings.OTP_MAX_ATTEMPTS - otp_record.attempts
            await self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Incorrect OTP. {remaining} attempt(s) remaining.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Success — burn the OTP immediately (single use)
        email = user.email_address
        user_id = user.id
        otp_record.is_used = True
        await self.session.commit()

        # Issue a token pair for the verified session
        access_token = token_access.create_access_token(data={"sub": email})
        raw_refresh, refresh_hash, rf_expires_at = token_access.create_refresh_token()

        refresh_record = RefreshToken(
            token_hash=refresh_hash,
            user_id=user_id,
            expires_at=rf_expires_at,
        )
        self.session.add(refresh_record)
        await self.session.commit()

        logger.info(f"OTP verified for {email}")
        return {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
        }

    async def refresh(self, request: RefreshRequest):
        token_hash = token_access._hash_token(request.refresh_token)

        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        record = result.scalars().first()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        if record.is_revoked:
            logger.warning(
                f"Refresh token reuse detected for family {record.family_id}. "
                "Revoking entire family."
            )
            await self._revoke_family(record.family_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token already used. Please log in again.",
            )

        now = datetime.now(timezone.utc)
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            record.is_revoked = True
            await self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired. Please log in again.",
            )

        user_result = await self.session.execute(
            select(User).where(User.id == record.user_id)
        )
        user = user_result.scalars().first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User no longer exists",
            )

        record.is_revoked = True

        access_token = token_access.create_access_token(data={"sub": user.email_address})
        raw_refresh, refresh_hash, new_expires_at = token_access.create_refresh_token()

        email = user.email_address
        new_record = RefreshToken(
            token_hash=refresh_hash,
            user_id=user.id,
            family_id=record.family_id,
            expires_at=new_expires_at,
        )
        self.session.add(new_record)
        await self.session.commit()

        logger.info(f"Tokens rotated for user: {email}")
        return {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
        }

    async def logout(self, request: LogoutRequest):
        token_hash = token_access._hash_token(request.refresh_token)

        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        record = result.scalars().first()

        if record and not record.is_revoked:
            user_id = record.user_id
            record.is_revoked = True
            await self.session.commit()
            logger.info(f"Refresh token revoked for user {user_id}")

        return {"message": "Logged out successfully"}

    async def change_password(self, password_change: PasswordChange):
        try:
            current_user = await self.authenticate_request(password_change)

            if not security.verify_password(password_change.current_password, current_user.password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if password_change.new_password != password_change.new_password_confirm:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Passwords do not match",
                )

            current_user.password = security.get_password_hash(password_change.new_password)
            self.session.add(current_user)
            await self.session.commit()
            await self.session.refresh(current_user)
            logger.info(f"Successfully changed password for user ID: {current_user.id}")

        except HTTPException:
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error during password change. Error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while changing the password.",
            )

    async def _revoke_family(self, family_id: UUID):
        """Revoke all tokens belonging to a refresh token family."""
        result = await self.session.execute(
            select(RefreshToken).where(
                RefreshToken.family_id == family_id,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
        )
        tokens = result.scalars().all()
        for t in tokens:
            t.is_revoked = True
        await self.session.commit()
        logger.warning(f"Revoked {len(tokens)} token(s) in family {family_id}")


auth_service = AuthService(session=SessionDep)