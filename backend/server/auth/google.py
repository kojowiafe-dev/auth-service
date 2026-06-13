"""
Google OAuth 2.0 helpers — Authorization Code Flow (server-side).

Architecture — why Authorization Code Flow?
────────────────────────────────────────────
  The client never receives a Google access token. The browser is redirected to
  Google, the user consents, and Google calls us back with a short-lived `code`.
  We exchange that code for tokens server-side (our client secret stays secret).
  We only use Google tokens to verify identity + fetch the profile, then issue
  our own JWT pair — the rest of the app is completely unaware of Google.

Flow:
  1. GET  /auth/google/login
        └─ redirect_to(get_google_auth_url())

  2. GET  /auth/google/callback?code=...&state=...
        ├─ exchange_code_for_token(code) → google_access_token
        ├─ get_google_user_info(google_access_token) → {id, email, name, picture}
        └─ AuthService.google_login(google_info) → {access_token, refresh_token}
"""

from urllib.parse import urlencode
import httpx

from server.config import settings


# Google OAuth endpoints
_AUTH_URL     = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL    = "https://oauth2.googleapis.com/token"
_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# Scopes we request: basic identity + email + profile picture
_SCOPES = "openid email profile"


def get_google_auth_url() -> str:
    """
    Build the Google consent-screen URL to redirect the user to.

    The `access_type=offline` param requests a refresh_token from Google
    (not used here, but good practice if you ever want to call Google APIs
    on behalf of the user later).
    `prompt=select_account` forces the account-picker even if the user is
    already signed in, preventing silent logins on shared machines.
    """
    params = {
        "client_id":     settings.GOOGLE_CLIENT_ID,
        "redirect_uri":  settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         _SCOPES,
        "access_type":   "offline",
        "prompt":        "select_account",
    }
    return f"{_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_token(code: str) -> str:
    """
    Exchange the one-time authorization `code` Google sent us for an
    access token we can use to call Google APIs.

    Returns the Google access_token string.
    Raises httpx.HTTPStatusError on a bad response from Google.
    """
    payload = {
        "code":          code,
        "client_id":     settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri":  settings.GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(_TOKEN_URL, data=payload)
        resp.raise_for_status()
        return resp.json()["access_token"]


async def get_google_user_info(access_token: str) -> dict:
    """
    Fetch the authenticated user's Google profile using their access token.

    Returns a dict with at least:
        {
            "id":      "<google-sub>",     # stable unique Google account ID
            "email":   "user@gmail.com",
            "name":    "Jane Doe",
            "picture": "https://...",      # profile photo URL (may be empty)
        }
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(_USERINFO_URL, headers=headers)
        resp.raise_for_status()
        return resp.json()
