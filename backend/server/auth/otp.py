import hashlib
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import status, HTTPException
from server.config import settings


def generate_otp() -> tuple[str, str]:
    """
    Generate a 6-digit OTP.

    Returns (raw_code, code_hash).
    Only the raw code is emailed to the user; only the hash is stored in DB.
    """
    raw = f"{random.randint(0, 999999):06d}"
    code_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, code_hash


def send_otp_email(email_address: str, username: str, otp: str) -> None:
    """
    Send an OTP email. Raises HTTPException on failure.

    The caller is responsible for generating the OTP and persisting its hash
    before calling this function.
    """
    try:
        msg = MIMEMultipart()
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = email_address
        msg["Subject"] = "Your verification code"
        body = (
            f"Hi {username},\n\n"
            f"Your one-time verification code is: {otp}\n\n"
            f"This code expires in {settings.RESET_TOKEN_EXPIRE_MINUTES} minutes "
            f"and can only be used once.\n\n"
            f"If you didn't request this, please ignore this email."
        )
        msg.attach(MIMEText(body, "plain"))

        if not (settings.SMTP_SERVER and settings.SMTP_PORT):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Email service is not configured.",
            )

        with smtplib.SMTP(settings.SMTP_SERVER, int(settings.SMTP_PORT)) as s:
            s.starttls()
            s.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            s.send_message(msg)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send OTP email: {e}",
        )