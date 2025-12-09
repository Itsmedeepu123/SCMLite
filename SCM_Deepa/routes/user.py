# app/routers/user.py

import os
import logging
import secrets
import hashlib
import uuid
import urllib.parse
import smtplib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from email.message import EmailMessage

# Third-party imports
import requests
import httpx     # For Google SSO
import pyotp     # For MFA
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr
from jose import JWTError

# Local imports
from core.database import users_collection, logins_collection, shipments_collection, db
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
router = APIRouter(tags=["User Authentication and Web"])
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

# MFA Config
MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "SCMXpertLite")

# OTP / Email Config
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
OTP_HASH_SECRET = os.getenv("OTP_HASH_SECRET", os.getenv("SECRET_KEY", "change_this_secret"))
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "0") or 0)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "no-reply@example.com")

# OAuth Scheme for API
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

# MongoDB Collection for Resets (Created dynamically if not in database.py)
password_resets_collection = db["password_resets"]

# MongoDB Collection for Email Logs
email_logs_collection = db["email_logs"]

# MongoDB Collection for Ratings
ratings_collection = db["ratings"]

# --- Helper Functions ---


def generate_numeric_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def hash_otp_for_storage(otp: str) -> str:
    h = hashlib.sha256()
    h.update((OTP_HASH_SECRET + otp).encode("utf-8"))
    return h.hexdigest()

def send_otp_email(to_email: str, otp: str) -> bool:
    # Enhanced email content with HTML for better deliverability
    reset_text = f"""Dear User,

You have requested a password reset for your SCMXpertLite account.

Your password reset code is: {otp}

This code will expire in {OTP_EXPIRE_MINUTES} minutes.

If you did not request this password reset, please ignore this email or contact our support team.

Thank you,
SCMXpertLite Team"""

    reset_html = f"""<html>
<head></head>
<body>
<h2>SCMXpertLite Password Reset</h2>
<p>Dear User,</p>
<p>You have requested a password reset for your SCMXpertLite account.</p>
<p>Your password reset code is: <strong>{otp}</strong></p>
<p>This code will expire in {OTP_EXPIRE_MINUTES} minutes.</p>
<p>If you did not request this password reset, please ignore this email or contact our support team.</p>
<br>
<p>Thank you,<br>
SCMXpertLite Team</p>
</body>
</html>"""

    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP not configured - printing OTP to logs for dev/testing.")
        logger.info(f"OTP for {to_email}: {otp}")
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = "SCMXpertLite - Password Reset Code"
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg.set_content(reset_text)
        msg.add_alternative(reset_html, subtype='html')

        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        logger.info(f"Sent OTP to {to_email}")
        
        # Log successful email sending
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "sent",
            "timestamp": datetime.now(timezone.utc),
            "details": "Email sent successfully"
        })
        return True
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"SMTP Recipients Refused - Email not sent to {to_email}: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPRecipientsRefused: {str(e)}"
        })
        return False
    except smtplib.SMTPHeloError as e:
        logger.error(f"SMTP HELO Error - Server didn't reply properly: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPHeloError: {str(e)}"
        })
        return False
    except smtplib.SMTPSenderRefused as e:
        logger.error(f"SMTP Sender Refused - From address rejected: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPSenderRefused: {str(e)}"
        })
        return False
    except smtplib.SMTPDataError as e:
        logger.error(f"SMTP Data Error - Unexpected reply: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPDataError: {str(e)}"
        })
        return False
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication Error - Username/password refused: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPAuthenticationError: {str(e)}"
        })
        return False
    except smtplib.SMTPException as e:
        logger.error(f"General SMTP Error: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPException: {str(e)}"
        })
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending OTP email to {to_email}: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"UnexpectedError: {str(e)}"
        })
        return False


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
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        response.raise_for_status()
        return response.json()

async def get_google_userinfo(access_token: str):
    userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(userinfo_url, headers=headers)
        response.raise_for_status()
        return response.json()

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
@limiter.limit("3/minute")
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
    
    # For non-admin users, redirect to MFA setup if MFA is not enabled
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

# --- Routes: Google SSO ---

@router.get("/auth/google/login", name="google_login", response_class=RedirectResponse)
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

# --- Routes: Forgot Password (OTP) ---

@router.get("/forgot-password", response_class=HTMLResponse, name="forgot_password_get")
def forgot_password_get(request: Request, message: str = None, error: str = None):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "message": message, "error": error})

@router.post("/forgot-password", response_class=RedirectResponse)
def forgot_password_post(request: Request, email: EmailStr = Form(...)):
    user = users_collection.find_one({"email": email})
    otp = generate_numeric_otp(OTP_LENGTH)
    otp_hash = hash_otp_for_storage(otp)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

    password_resets_collection.delete_many({"email": email, "used": False})

    password_resets_collection.insert_one({
        "email": email,
        "otp_hash": otp_hash,
        "created_at": now,
        "expires_at": expires_at,
        "used": False,
        "reset_token": None
    })

    email_sent = False
    if user:
        # Try to send email up to 3 times for better reliability
        for attempt in range(3):
            email_sent = send_otp_email(email, otp)
            if email_sent:
                break
            else:
                logger.warning(f"Email sending attempt {attempt + 1} failed for {email}. Retrying...")
                # Wait a bit before retrying
                import time
                time.sleep(1)
    
    # Log the email request regardless of whether user exists (for security)
    logger.info(f"OTP requested for email: {email}")

    if user and not email_sent:
        # Email sending failed after all retries
        return RedirectResponse(url=f"/forgot-password?error=Failed+to+send+email.+Please+try+again+later.+Check+your+spam+junk+folder.", status_code=status.HTTP_303_SEE_OTHER)
    elif not user:
        # Don't reveal if user exists or not for security
        logger.info(f"OTP requested for non-existent email: {email}")

    return RedirectResponse(url=f"/verify-otp?email={urllib.parse.quote_plus(email)}&message=Password+reset+code+sent.+Check+your+inbox+and+spam+junk+folder.", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/verify-otp", response_class=HTMLResponse, name="verify_otp_get")
def verify_otp_get(request: Request, email: str = None, message: str = None, error: str = None):
    if not email:
        return RedirectResponse(url="/forgot-password?error=Missing+email", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("verify_otp.html", {"request": request, "email": email, "message": message, "error": error})

@router.post("/verify-otp", response_class=RedirectResponse, name="verify_otp_post")
def verify_otp_post(request: Request, email: EmailStr = Form(...), otp: str = Form(...)):
    now = datetime.now(timezone.utc)
    doc = password_resets_collection.find_one({"email": email, "used": False, "expires_at": {"$gt": now}}, sort=[("created_at", -1)])
    
    if not doc or hash_otp_for_storage(otp) != doc["otp_hash"]:
        return RedirectResponse(url=f"/verify-otp?email={urllib.parse.quote_plus(email)}&error=Invalid+OTP", status_code=status.HTTP_303_SEE_OTHER)

    reset_token = uuid.uuid4().hex
    token_expires_at = now + timedelta(minutes=15)

    password_resets_collection.update_one(
        {"_id": doc["_id"]},
        {"$set": {"reset_token": reset_token, "token_expires_at": token_expires_at, "used": False}, "$unset": {"otp_hash": ""}}
    )

    return RedirectResponse(url=f"/reset-password?token={urllib.parse.quote_plus(reset_token)}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/reset-password", response_class=HTMLResponse, name="reset_password_get")
def reset_password_get(request: Request, token: str = None, error: str = None):
    if not token:
        return RedirectResponse(url="/forgot-password?error=Missing+token", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@router.post("/reset-password", response_class=RedirectResponse, name="reset_password_post")
def reset_password_post(request: Request, token: str = Form(...), password: str = Form(...), confirm_password: str = Form(...)):
    if password != confirm_password:
        return RedirectResponse(url=f"/reset-password?token={urllib.parse.quote_plus(token)}&error=Passwords+do+not+match", status_code=status.HTTP_303_SEE_OTHER)

    now = datetime.now(timezone.utc)
    doc = password_resets_collection.find_one({"reset_token": token, "used": False, "token_expires_at": {"$gt": now}})
    if not doc:
        return RedirectResponse(url="/forgot-password?error=Invalid+token", status_code=status.HTTP_303_SEE_OTHER)

    users_collection.update_one(
        {"email": doc["email"]}, 
        {"$set": {"password_hash": get_password_hash(password), "password_changed_at": datetime.now(timezone.utc)}}
    )
    password_resets_collection.update_one({"_id": doc["_id"]}, {"$set": {"used": True}})

    return RedirectResponse(url="/login?message=Password+reset+success", status_code=status.HTTP_303_SEE_OTHER)

# --- Routes: MFA Setup for Login ---
@router.get("/mfa/setup-for-login", response_class=HTMLResponse)
def mfa_setup_for_login_get(request: Request, email: str = None):
    if not email:
        return RedirectResponse(url="/login?error=Missing+email", status_code=status.HTTP_303_SEE_OTHER)
    
    # Check if user exists
    user = users_collection.find_one({"email": email})
    if not user:
        return RedirectResponse(url="/login?error=User+not+found", status_code=status.HTTP_303_SEE_OTHER)
    
    # Admins don't need to go through this flow
    if user.get("role") == "admin":
        return RedirectResponse(url="/login?error=Admins+don't+need+MFA+setup", status_code=status.HTTP_303_SEE_OTHER)
    
    # Generate a new secret for MFA setup
    secret = pyotp.random_base32()
    message = "Set up Multi-Factor Authentication"
    
    # Generate provisioning URI and QR code data
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=MFA_ISSUER_NAME
    )
    
    qr_code_data = pyotp.utils.build_uri(
        secret=secret,
        name=email,
        issuer=MFA_ISSUER_NAME
    )
    
    # Generate QR code
    import qrcode
    import io
    import base64
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
    except Exception as e:
        # Log the error and return a fallback
        logger.error(f"Error generating QR code: {str(e)}")
        qr_code_b64 = ""
    
    return templates.TemplateResponse("mfa_setup.html", {
        "request": request,
        "mfa_data": {
            "secret": secret,
            "qr_code_data": qr_code_b64
        },
        "message": message,
        "for_login": True,  # Flag to indicate this is for login flow
        "user_email": email  # Pass email for form submission
    })

@router.post("/mfa/setup-for-login", response_class=RedirectResponse)
def mfa_setup_for_login_post(
    request: Request,
    secret: str = Form(...),
    token: str = Form(...),
    email: str = Form(...)
):
    # Verify the TOTP token
    totp = pyotp.TOTP(secret)
    if not totp.verify(token):
        # Regenerate QR code for retry
        qr_code_data = pyotp.utils.build_uri(
            secret=secret,
            name=email,
            issuer=MFA_ISSUER_NAME
        )
        
        import qrcode
        import io
        import base64
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return templates.TemplateResponse("mfa_setup.html", {
            "request": request,
            "error": "Invalid token. Please try again.",
            "mfa_data": {
                "secret": secret,
                "qr_code_data": qr_code_b64
            },
            "for_login": True,  # Flag to indicate this is for login flow
            "user_email": email  # Pass email for form submission
        }, status_code=400)
    
    # Save MFA secret to user document and enable MFA
    users_collection.update_one(
        {"email": email},
        {"$set": {"mfa_secret": secret, "mfa_enabled": True}}
    )
    
    # Now redirect to MFA verification
    return RedirectResponse(url=f"/mfa/verify?email={urllib.parse.quote_plus(email)}", status_code=status.HTTP_303_SEE_OTHER)

# --- Routes: MFA Setup (for profile) ---
@router.get("/mfa/setup", response_class=HTMLResponse)
def mfa_setup_get(request: Request, current_user: dict = Depends(get_required_current_user)):
    # Admins can now configure MFA
    # Check if user already has MFA enabled
    user = users_collection.find_one({"email": current_user["email"]})
    
    # For existing users with MFA, we'll show their current setup
    # For new users or users reconfiguring, we'll generate a new secret
    if user and user.get("mfa_secret") and user.get("mfa_enabled"):
        # Existing user with MFA enabled - show their current setup
        secret = user.get("mfa_secret")
        message = "Your MFA is already configured. Scan the QR code below with your authenticator app."
    else:
        # New user or reconfiguring - generate new secret
        secret = pyotp.random_base32()
        message = "Set up Multi-Factor Authentication"
    
    # Generate provisioning URI and QR code data
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user["email"],
        issuer_name=MFA_ISSUER_NAME
    )
    
    qr_code_data = pyotp.utils.build_uri(
        secret=secret,
        name=current_user["email"],
        issuer=MFA_ISSUER_NAME
    )
    
    # Generate QR code
    import qrcode
    import io
    import base64
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
    except Exception as e:
        # Log the error and return a fallback
        logger.error(f"Error generating QR code: {str(e)}")
        qr_code_b64 = ""
    
    return templates.TemplateResponse("mfa_setup.html", {
        "request": request,
        "mfa_data": {
            "secret": secret,
            "qr_code_data": qr_code_b64
        },
        "message": message
    })

@router.post("/mfa/verify-setup", response_class=RedirectResponse)
def mfa_verify_setup_post(
    request: Request,
    secret: str = Form(...),
    token: str = Form(...),
    current_user: dict = Depends(get_required_current_user)
):
    # Verify the TOTP token
    totp = pyotp.TOTP(secret)
    if not totp.verify(token):
        # Regenerate QR code for retry
        qr_code_data = pyotp.utils.build_uri(
            secret=secret,
            name=current_user["email"],
            issuer=MFA_ISSUER_NAME
        )
        
        import qrcode
        import io
        import base64
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return templates.TemplateResponse("mfa_setup.html", {
            "request": request,
            "error": "Invalid token. Please try again.",
            "mfa_data": {
                "secret": secret,
                "qr_code_data": qr_code_b64
            }
        }, status_code=400)
    
    # Save MFA secret to user document
    users_collection.update_one(
        {"email": current_user["email"]},
        {"$set": {"mfa_secret": secret, "mfa_enabled": True}}
    )
    
    return RedirectResponse(url="/user-profile?message=MFA+enabled+successfully", status_code=status.HTTP_303_SEE_OTHER)

# --- Routes: MFA Verification (during login) ---
@router.get("/mfa/verify", response_class=HTMLResponse)
def mfa_verify_get(request: Request, email: str = None):
    if not email:
        return RedirectResponse(url="/login?error=Missing+email", status_code=status.HTTP_303_SEE_OTHER)
    
    # Check if user has MFA enabled
    user = users_collection.find_one({"email": email})
    # Admins can have MFA if they choose to enable it
    if not user or not user.get("mfa_enabled"):
        # For users without MFA, redirect to appropriate dashboard
        if user:
            token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
                expires_delta=token_expires
            )
            
            redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
            response = RedirectResponse(url=f"{redirect_url}?message=Successfully+logged+in", status_code=status.HTTP_303_SEE_OTHER)
            
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
        return RedirectResponse(url="/login?error=User+not+found+or+MFA+not+enabled", status_code=status.HTTP_303_SEE_OTHER)
    
    # Generate QR code for MFA verification
    secret = user.get("mfa_secret")
    qr_code_data = pyotp.utils.build_uri(
        secret=secret,
        name=email,
        issuer=MFA_ISSUER_NAME
    )
    
    import qrcode
    import io
    import base64
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_code_data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
    
    return templates.TemplateResponse("mfa_verify.html", {
        "request": request,
        "mfa_data": {
            "secret": secret,
            "qr_code_data": qr_code_b64
        },
        "email": email,
        "mfa_already_setup": True
    })

@router.post("/mfa/verify", response_class=RedirectResponse)
def mfa_verify_post(
    request: Request,
    token: str = Form(...),
    email: str = Form(...)
):
    # Get user with MFA enabled
    user = users_collection.find_one({"email": email, "mfa_enabled": True})
    if not user:
        return RedirectResponse(url="/login?error=User+not+found+or+MFA+not+enabled", status_code=status.HTTP_303_SEE_OTHER)
    
    # Verify the TOTP token
    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(token):
        # Generate QR code for retry
        qr_code_data = pyotp.utils.build_uri(
            secret=user["mfa_secret"],
            name=email,
            issuer=MFA_ISSUER_NAME
        )
        
        import qrcode
        import io
        import base64
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
        
        return templates.TemplateResponse("mfa_verify.html", {
            "request": request,
            "error": "Invalid token. Please try again.",
            "mfa_data": {
                "secret": user["mfa_secret"],
                "qr_code_data": qr_code_b64
            },
            "email": email,
            "mfa_already_setup": True
        }, status_code=400)
    
    # MFA verified, create access token and log in user
    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
        expires_delta=token_expires
    )
    
    logins_collection.insert_one({
        "email": email,
        "login_time": datetime.now(timezone.utc),
        "status": "success_mfa",
        "ip_address": request.client.host if request.client else "unknown"
    })
    
    redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
    response = RedirectResponse(url=f"{redirect_url}?message=Successfully+logged+in", status_code=status.HTTP_303_SEE_OTHER)
    
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

# --- Routes: Disable MFA ---
@router.post("/mfa/disable", response_class=RedirectResponse)
def mfa_disable_post(request: Request, current_user: dict = Depends(get_required_current_user)):
    # Admins can now disable MFA
    users_collection.update_one(
        {"email": current_user["email"]},
        {"$unset": {"mfa_secret": "", "mfa_enabled": ""}}
    )
    
    return RedirectResponse(url="/user-profile?message=MFA+disabled+successfully", status_code=status.HTTP_303_SEE_OTHER)

# --- Routes: Protected Pages ---

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, current_user: dict = Depends(get_required_current_user)):
    if current_user.get("role") == "admin":
        return RedirectResponse(url="/admin-dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "message": request.query_params.get("message")
    })

@router.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, current_user: dict = Depends(get_current_admin_user)):
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "user": current_user,
        "message": request.query_params.get("message")
    })

@router.get("/admin-email-logs", response_class=HTMLResponse)
def get_admin_email_logs(request: Request, current_user: dict = Depends(get_current_admin_user)):
    # Get all email logs from the database
    email_logs = list(email_logs_collection.find().sort("timestamp", -1).limit(100))
    
    # Format timestamps for display
    for log in email_logs:
        log["_id"] = str(log["_id"])
        if "timestamp" in log and hasattr(log["timestamp"], 'isoformat'):
            log["timestamp"] = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC")
    
    return templates.TemplateResponse("admin_email_logs.html", {
        "request": request,
        "user": current_user,
        "email_logs": email_logs
    })

@router.get("/admin-ratings", response_class=HTMLResponse)
def get_admin_ratings(request: Request, current_user: dict = Depends(get_current_admin_user)):
    # Get all ratings from the database
    ratings = list(ratings_collection.find().sort("created_at", -1))
    
    # Enhance ratings with user role information
    for rating in ratings:
        # Get user details from database
        user = users_collection.find_one({"email": rating["user_email"]})
        rating["user_role"] = user.get("role", "user") if user else "user"
        
        # Convert ObjectId to string for JSON serialization
        rating["_id"] = str(rating["_id"])
        if "created_at" in rating and hasattr(rating["created_at"], 'isoformat'):
            rating["created_at"] = rating["created_at"].isoformat()
    
    return templates.TemplateResponse("admin_ratings.html", {
        "request": request,
        "user": current_user,
        "ratings": ratings
    })

@router.get("/user-profile", response_class=HTMLResponse)
def get_user_profile(request: Request, current_user: dict = Depends(get_required_current_user)):
    user_email = current_user.get("email")  # Use email instead of name for consistency
    user = users_collection.find_one({"email": user_email})
    # Fetch shipments using the user's name to match the created_by field
    user_name = current_user.get("name", "unknown")
    shipments = list(shipments_collection.find({"created_by": user_name}))
    for shipment in shipments:
        shipment["_id"] = str(shipment["_id"])

    # Add MFA status to user data
    user_data = {
        "email": user["email"],
        "name": user.get("name"),
        "role": user.get("role", "user"),
        "mfa_enabled": user.get("mfa_enabled", False)
    }

    return templates.TemplateResponse("user-profile.html", {
        "request": request,
        "user": user_data,
        "shipments": shipments
    })

# --- Routes: API ---

@router.post("/api/login", response_class=JSONResponse)
@limiter.limit("10/minute")
async def api_login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
        expires_delta=token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(token_expires.total_seconds())
    }

@router.get("/me", response_class=JSONResponse)
async def read_users_me(current_user: dict = Depends(get_required_current_user)):
    return current_user

# --- Swagger UI Auth Helper ---

async def get_current_user_from_bearer_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_token(token)
        email = payload.get("sub")
        if not email:
             raise HTTPException(status_code=401, detail="Invalid token")
        
        user = users_collection.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return {"email": user["email"], "name": user.get("name"), "role": user.get("role", "user")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/submit-rating", response_class=JSONResponse)
async def submit_rating(
    request: Request, 
    rating: int = Form(...), 
    comment: str = Form(None),
    current_user: dict = Depends(get_required_current_user)
):
    try:
        # Get user from database to get the _id
        user_db = users_collection.find_one({"email": current_user["email"]})
        if not user_db:
            return JSONResponse({"status": "error", "message": "User not found"}, status_code=404)
        
        # Create rating document
        rating_doc = {
            "user_id": str(user_db["_id"]),
            "user_email": current_user["email"],
            "rating": rating,
            "comment": comment,
            "created_at": datetime.utcnow()
        }
        
        # Insert into database
        result = ratings_collection.insert_one(rating_doc)
        
        return JSONResponse({"status": "success", "message": "Rating submitted successfully"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


@router.get("/api/v1/test-swagger-auth", tags=["API Authentication Test"], summary="Test Bearer Auth")
async def test_swagger_auth(current_api_user: dict = Depends(get_current_user_from_bearer_token)):
    return {"message": "Authenticated!", "user": current_api_user}


