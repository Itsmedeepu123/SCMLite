import os
import logging
from datetime import datetime, timedelta, timezone
import urllib.parse

# Third-party imports
import pyotp
import qrcode
import io
import base64
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# Local imports
from core.database import users_collection, logins_collection
from core.auth import (
    create_access_token, get_required_current_user
)
from core.config import ACCESS_TOKEN_EXPIRE_MINUTES

# Load Environment
load_dotenv()
logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["MFA"])
templates = Jinja2Templates(directory="templates")

# --- Configuration & Constants ---
COOKIE_SECURE_ENABLED = os.getenv("COOKIE_SECURE_FLAG", "False").lower() == "true"
COOKIE_SAMESITE_POLICY = "none" if COOKIE_SECURE_ENABLED else "lax"

# MFA Config
MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "SCMXpertLite")

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
            "user_email": email  # Pass email form submission
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