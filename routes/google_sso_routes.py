import os
import logging
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone

# Third-party imports
import httpx
import certifi
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# Local imports
from core.database import users_collection, logins_collection, db
from core.auth import (
    create_access_token, decode_token
)
from core.limiter import limiter

# Load Environment
load_dotenv()
logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["Google SSO"])
templates = Jinja2Templates(directory="templates")

# --- Configuration & Constants ---
COOKIE_SECURE_ENABLED = os.getenv("COOKIE_SECURE_FLAG", "False").lower() == "true"
COOKIE_SAMESITE_POLICY = "none" if COOKIE_SECURE_ENABLED else "lax"

# Google SSO Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
GOOGLE_OAUTH_SCOPES = os.getenv("GOOGLE_OAUTH_SCOPES", "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile")
GOOGLE_OAUTH_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"

# Access Token Config
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# --- Google SSO Helpers ---
def build_google_auth_url(state: str) -> str:
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": GOOGLE_OAUTH_SCOPES,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "state": state,
        "access_type": "offline",
        "prompt": "select_account"
    }
    return f"{GOOGLE_OAUTH_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

async def exchange_code_for_tokens(code: str, redirect_uri: str):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    # Configure HTTP client with certifi certificates for better cross-platform compatibility
    async with httpx.AsyncClient(verify=certifi.where()) as client:
        response = await client.post(token_url, data=data)
        response.raise_for_status()
        return response.json()

async def get_google_userinfo(access_token: str):
    userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    # Configure HTTP client with certifi certificates for better cross-platform compatibility
    async with httpx.AsyncClient(verify=certifi.where()) as client:
        response = await client.get(userinfo_url, headers=headers)
        response.raise_for_status()
        return response.json()

# --- Routes: Google SSO ---
@router.get("/auth/google/login", name="google_login", response_class=RedirectResponse)
@limiter.limit("10/minute")
def google_login(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("[GOOGLE SSO] Missing client id/secret in env")
        return RedirectResponse(url="/login?error=Google+SSO+not+configured", status_code=status.HTTP_303_SEE_OTHER)

    state = secrets.token_urlsafe(32)
    auth_url = build_google_auth_url(state)

    response = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        "oauth_state",
        state,
        max_age=300,
        httponly=True,
        secure=COOKIE_SECURE_ENABLED,
        samesite=COOKIE_SAMESITE_POLICY,
        path="/"
    )
    return response

@router.get("/auth/google/callback", response_class=RedirectResponse)
@limiter.limit("2/minute")
async def google_callback(request: Request, code: str = None, state: str = None, error: str = None):
    if error:
        return RedirectResponse(url="/login?error=Google+login+failed", status_code=status.HTTP_303_SEE_OTHER)

    if not code or not state:
        return RedirectResponse(url="/login?error=Missing+code+or+state", status_code=status.HTTP_303_SEE_OTHER)

    cookie_state = request.cookies.get("oauth_state")
    if not cookie_state or cookie_state != state:
        resp = RedirectResponse(url="/login?error=Invalid+OAuth+state", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp

    try:
        # 1. Exchange Code
        token_resp = await exchange_code_for_tokens(code, GOOGLE_REDIRECT_URI)
        access_token_google = token_resp.get("access_token")
        
        if not access_token_google:
            resp = RedirectResponse(url="/login?error=Google+token+failed", status_code=status.HTTP_303_SEE_OTHER)
            resp.delete_cookie("oauth_state", path="/")
            return resp

        # 2. Get User Info
        userinfo = await get_google_userinfo(access_token_google)
        email = userinfo.get("email")
        name = userinfo.get("name") or userinfo.get("given_name") or "User"

        if not email:
            resp = RedirectResponse(url="/login?error=Google+email+missing", status_code=status.HTTP_303_SEE_OTHER)
            resp.delete_cookie("oauth_state", path="/")
            return resp

        # 3. DB Logic
        user = users_collection.find_one({"email": email})
        if not user:
            users_collection.insert_one({
                "name": name,
                "email": email,
                "password_hash": "", # SSO User
                "role": "user",
                "created_at": datetime.now(timezone.utc),
                "email_verified": True,
                "sso_provider": "google",
                "sso_sub": userinfo.get("sub")
            })
            user = users_collection.find_one({"email": email})

        # 4. For SSO users, we bypass MFA requirement
        # Note: Admins don't need MFA anyway, and regular users logging in via SSO are trusted
        # Only require MFA for password-based logins

        # 5. Login Logging
        logins_collection.insert_one({
            "email": email,
            "login_time": datetime.now(timezone.utc),
            "status": "success_google_sso",
            "ip_address": request.client.host if request.client else "unknown"
        })

        # 6. Create Token & Response
        token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
            expires_delta=token_expires
        )

        redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
        resp = RedirectResponse(url=f"{redirect_url}?message=Login+successful", status_code=status.HTTP_303_SEE_OTHER)

        resp.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=COOKIE_SECURE_ENABLED,
            max_age=int(token_expires.total_seconds()),
            samesite=COOKIE_SAMESITE_POLICY,
            path="/"
        )
        for key, val in [("user_name", user.get("name", "")), ("user_email", user["email"]), ("user_role", user.get("role", "user"))]:
            resp.set_cookie(key=key, value=val, secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
        
        resp.delete_cookie("oauth_state", path="/")
        return resp

    except Exception as e:
        logger.exception(f"[GOOGLE SSO] Error: {e}")
        resp = RedirectResponse(url="/login?error=SSO+Error", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp