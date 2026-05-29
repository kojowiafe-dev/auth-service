import random
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from fastapi import status, HTTPException

from fastapi.responses import JSONResponse
from server.config import settings


def get_otp() -> str:
    """
    Generate a random 6 digit OTP.
    """
    return f"{random.randint(0, 999999):06d}"


def send_email(email_address: str, username: str):
    try:
        otp = get_otp()
        print(f"Generated OTP: {otp}")
        msg = MIMEMultipart()
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = email_address
        msg["Subject"] = "OTP Verification"
        body = f"Hello {username}, Your OTP is {otp}"
        msg.attach(MIMEText(body, "plain"))

        if settings.SMTP_SERVER and settings.SMTP_PORT:
            with smtplib.SMTP(settings.SMTP_SERVER, int(settings.SMTP_PORT)) as s:
                s.starttls()
                s.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                s.send_message(msg)
            print("Email successfully sent via SMTP.")
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "message": "OTP sent successfully",
                    "otp": otp
                },
            )
        else:
            print("Warning: SMTP is not configured in settings. Email was not sent.")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "message": "Email not sent"
                },
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# try:
#     send_email("kojowiafe502@gmail.com", "Jeremiah Wiafe")
# except Exception as e:
#     print(e)