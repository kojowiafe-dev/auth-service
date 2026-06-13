from fastapi import APIRouter, status, Request, Response, Depends
from fastapi.responses import RedirectResponse
from loguru import logger
import httpx

from server.auth.models import AuthBase, PasswordChange, OtpRequest, RefreshRequest, LogoutRequest
from server.database.core import SessionDep
from server.auth.service import AuthService
from server.dependencies import CurrentUser
from server.rate_limit import RateLimiter
from server.auth.google import get_google_auth_url, exchange_code_for_token, get_google_user_info
from server.config import settings


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def _get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address.

    Architecture note — X-Forwarded-For:
      When your server sits behind a reverse proxy (Nginx, AWS ALB, Cloudflare),
      the proxy terminates the TCP connection, so request.client.host is always
      the proxy's IP, not the user's. The proxy adds the original IP in the
      X-Forwarded-For header.

      Format:  X-Forwarded-For: <client IP>, <proxy1>, <proxy2>
      We take the FIRST value (leftmost), which is the original client.

      Important: only trust X-Forwarded-For if your proxy is configured to
      set it. If you're running without a proxy, rely on request.client.host.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    request: AuthBase,
    session: SessionDep,
    http_request: Request,
):
    logger.info(f"Registering user: {request.email_address}")
    return await AuthService(session=session).register(request=request)


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
    request: AuthBase,
    session: SessionDep,
    http_request: Request,
    response: Response,
    # Rate limiting dependency: max N requests per IP per window.
    # Injected automatically by FastAPI — no manual call needed.
    # Exceeding the limit raises HTTP 429 before the route body runs.
    _rate_limit: None = Depends(
        RateLimiter(
            max_requests=settings.LOGIN_RATE_LIMIT_MAX,
            window_seconds=settings.LOGIN_RATE_LIMIT_WINDOW,
            prefix="login",
        )
    ),
):
    """
    Authenticate and return an access + refresh token pair.

    Security layers (in order of execution):
      1. Rate limiter (Redis)   — max 10 attempts/60s per IP → HTTP 429
      2. Account lockout (DB)   — locked after 5 wrong passwords → HTTP 423
      3. Password check         — wrong password → HTTP 401
      4. IP audit log           — written on every attempt
      5. Device fingerprint     — registered / updated on success
    """
    ip = _get_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent", "")
    logger.info(f"Login attempt: {request.email_address} from {ip}")
    return await AuthService(session=session).login(
        request=request,
        ip_address=ip,
        user_agent=user_agent,
    )


@router.post("/refresh", status_code=status.HTTP_200_OK)
async def refresh_tokens(
    request: RefreshRequest,
    session: SessionDep,
):
    """
    Exchange a valid refresh token for a new access + refresh token pair.
    The old refresh token is immediately invalidated (one-time use).
    """
    return await AuthService(session=session).refresh(request=request)


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    request: LogoutRequest,
    session: SessionDep,
):
    """
    Revoke the provided refresh token, effectively ending the session.
    """
    return await AuthService(session=session).logout(request=request)


@router.patch("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_change: PasswordChange,
    session: SessionDep,
    user: CurrentUser,
):
    logger.info(f"Changing password for user: {user.email_address}")
    return await AuthService(session=session).change_password(
        password_change=password_change,
    )


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    request: AuthBase,
    session: SessionDep,
    http_request: Request,
    response: Response,
    _rate_limit: None = Depends(
        RateLimiter(
            max_requests=5,       # stricter: 5 OTP requests per 60s per IP
            window_seconds=60,
            prefix="forgot_password",
        )
    ),
):
    logger.info(f"Forgot password request for user: {request.email_address}")
    return await AuthService(session=session).forgot_password(request=request)


@router.post("/verify-otp", status_code=status.HTTP_200_OK)
async def verify_otp(
    request: OtpRequest,
    session: SessionDep,
):
    """
    Verify a one-time password. Returns a token pair on success.
    Enforces a {OTP_MAX_ATTEMPTS}-attempt limit and expiry window.
    """
    return await AuthService(session=session).authenticate_request(request=request)


# ── Google OAuth ──────────────────────────────────────────────────────────────

@router.get("/google/login")
async def google_login():
    """
    Redirect the user to Google's consent screen.

    The client simply navigates to this URL. Google will redirect back to
    /auth/google/callback with a one-time `code` after the user consents.
    """
    url = get_google_auth_url()
    return RedirectResponse(url=url, status_code=302)


@router.get("/google/callback", status_code=status.HTTP_200_OK)
async def google_callback(
    code: str,
    request: Request,
    session: SessionDep,
):
    """
    Handle the OAuth callback from Google.

    Google redirects here with a short-lived `code`. We:
      1. Exchange the code for a Google access token
      2. Fetch the user's Google profile
      3. Find-or-create / auto-link the local User account
      4. Return our own JWT access + refresh token pair

    On any Google API error we return HTTP 400 so the client knows
    to restart the OAuth flow.
    """
    ip          = _get_client_ip(request)
    user_agent  = request.headers.get("User-Agent", "")

    try:
        google_access_token = await exchange_code_for_token(code)
        google_info         = await get_google_user_info(google_access_token)
    except httpx.HTTPStatusError as exc:
        logger.warning(f"Google OAuth token exchange failed: {exc.response.text}")
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google authentication failed. Please try again.",
        )

    return await AuthService(session=session).google_login(
        google_info=google_info,
        ip_address=ip,
        user_agent=user_agent,
    )