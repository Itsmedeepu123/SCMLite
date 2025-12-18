import os
import logging
import secrets
import hashlib
import urllib.parse
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

# Third-party imports
import requests
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr
from jose import JWTError

# Local imports
from core.database import users_collection, logins_collection, db
from core.auth import (
    verify_password, get_password_hash, create_access_token,
    decode_token, get_required_current_user,
    get_current_admin_user
)
from core.limiter import limiter
from core.config import (
    RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Load Environment
load_dotenv()
logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["Authentication"])
templates = Jinja2Templates(directory="templates")

# --- Configuration & Constants ---
COOKIE_SECURE_ENABLED = os.getenv("COOKIE_SECURE_FLAG", "False").lower() == "true"
COOKIE_SAMESITE_POLICY = "none" if COOKIE_SECURE_ENABLED else "lax"

# OTP / Email Config
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
OTP_HASH_SECRET = os.getenv("OTP_HASH_SECRET", os.getenv("SECRET_KEY", "change_this_secret"))
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "0") or 0)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "no-reply@example.com")

# MongoDB Collection for Resets
password_resets_collection = db["password_resets"]

# MongoDB Collection for Email Logs
email_logs_collection = db["email_logs"]

# --- Helper Functions ---
def generate_numeric_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def hash_otp_for_storage(otp: str) -> str:
    h = hashlib.sha256()
    h.update((OTP_HASH_SECRET + otp).encode("utf-8"))
    return h.hexdigest()

def verify_recaptcha(token: str) -> bool:
    if not RECAPTCHA_SECRET_KEY:
        logger.warning("RECAPTCHA_SECRET_KEY is not set. Skipping verification.")
        return True
    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": token},
            timeout=5
        )
        response.raise_for_status()
        return response.json().get("success", False)
    except requests.exceptions.RequestException as e:
        logger.error(f"reCAPTCHA verification failed: {str(e)}")
        return False

# --- Routes: Standard Auth ---
@router.get("/", response_class=RedirectResponse)
def root(request: Request):
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except Exception:
            response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie("access_token")
            return response
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/login", response_class=HTMLResponse)
def get_login(request: Request, error: str = None, message: str = None, email: str = None):
    # Check if already logged in
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except JWTError:
            pass 

    return templates.TemplateResponse("login.html", {
        "request": request,
        "site_key": RECAPTCHA_SITE_KEY,
        "error": error,
        "message": message,
        "email_value": email
    })

@router.post("/login", response_class=RedirectResponse)
@limiter.limit("2/minute")
async def post_login(
    request: Request,
    username: EmailStr = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(..., alias="g-recaptcha-response"),
):
    if not verify_recaptcha(g_recaptcha_response):
        return RedirectResponse(url="/login?error=reCAPTCHA+failed", status_code=status.HTTP_303_SEE_OTHER)

    user = users_collection.find_one({"email": username})
    if not user or not verify_password(password, user["password_hash"]):
        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.now(timezone.utc),
            "status": "failed",
            "ip_address": request.client.host if request.client else "unknown"
        })
        return RedirectResponse(url=f"/login?error=Invalid+credentials&email={username}", status_code=status.HTTP_303_SEE_OTHER)

    # Check if user has MFA enabled (admins can now have MFA)
    if user.get("mfa_enabled"):
        # Redirect to MFA verification page
        return RedirectResponse(url=f"/mfa/verify?email={urllib.parse.quote_plus(username)}", status_code=status.HTTP_303_SEE_OTHER)
    
    # For non-admin users
    if user.get("role") != "admin":
        # Redirect to MFA setup page for all non-admin users (new and existing)
        return RedirectResponse(url=f"/mfa/setup-for-login?email={urllib.parse.quote_plus(username)}", status_code=status.HTTP_303_SEE_OTHER)
    
    # For admin users without MFA, proceed to dashboard
    redirect_url = "/admin-dashboard"
    
    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
        expires_delta=token_expires
    )

    logins_collection.insert_one({
        "email": username,
        "login_time": datetime.now(timezone.utc),
        "status": "success",
        "ip_address": request.client.host if request.client else "unknown"
    })

    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE_ENABLED,
        max_age=int(token_expires.total_seconds()),
        samesite=COOKIE_SAMESITE_POLICY,
        path="/"
    )
    # Utility cookies for JS (Not HttpOnly)
    for key, val in [("user_name", user.get("name", "")), ("user_email", user["email"]), ("user_role", user.get("role", "user"))]:
        response.set_cookie(key=key, value=val, secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
    
    return response

@router.get("/logout", response_class=RedirectResponse)
def logout(request: Request):
    response = RedirectResponse(url="/login?message=Logged+out+successfully", status_code=status.HTTP_303_SEE_OTHER)
    for cookie in ["access_token", "user_email", "user_role", "user_name"]:
        response.delete_cookie(cookie, path="/", secure=COOKIE_SECURE_ENABLED, samesite=COOKIE_SAMESITE_POLICY)
    return response

# --- Routes: Signup ---
@router.get("/signup", response_class=HTMLResponse)
def get_signup(request: Request, error: str = None):
    # Check if already logged in
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except Exception:
            pass
    return templates.TemplateResponse("signup.html", {
        "request": request,
        "error": error,
        "site_key": RECAPTCHA_SITE_KEY 
    })

@router.post("/signup", response_class=RedirectResponse)
def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    if password != confirm_password:
        return RedirectResponse(url="/signup?error=Passwords+do+not+match", status_code=status.HTTP_303_SEE_OTHER)

    if users_collection.find_one({"email": email}):
        return RedirectResponse(url="/signup?error=Email+already+registered", status_code=status.HTTP_303_SEE_OTHER)

    # Basic role logic
    role = "admin" if email.endswith("@admin.com") else "user"
    
    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": get_password_hash(password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
        "email_verified": False 
    })

    return RedirectResponse(url="/login?message=Account+created+successfully.+Please+log+in.", status_code=status.HTTP_303_SEE_OTHER)