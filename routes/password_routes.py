import os
import logging
import secrets
import hashlib
import uuid
import urllib.parse
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

# Third-party imports
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr

# Local imports
from core.database import users_collection, db
from core.auth import get_password_hash
from core.config import ACCESS_TOKEN_EXPIRE_MINUTES

# Load Environment
load_dotenv()
logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["Password Management"])
templates = Jinja2Templates(directory="templates")

# --- Configuration & Constants ---
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

def send_password_reset_confirmation_email(to_email: str) -> bool:
    """Send a confirmation email after password has been successfully reset."""
    # Enhanced email content with HTML for better deliverability
    reset_text = f"""Dear User,

Your password for your SCMXpertLite account has been successfully updated.

If you did not initiate this password change, please contact our support team immediately.

Thank you,
SCMXpertLite Team"""

    reset_html = f"""<html>
<head></head>
<body>
<h2>SCMXpertLite Password Updated</h2>
<p>Dear User,</p>
<p>Your password for your SCMXpertLite account has been successfully updated.</p>
<p>If you did not initiate this password change, please contact our support team immediately.</p>
<br>
<p>Thank you,<br>
SCMXpertLite Team</p>
</body>
</html>"""

    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP not configured - skipping password reset confirmation email.")
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = "SCMXpertLite - Password Successfully Updated"
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
        logger.info(f"Sent password reset confirmation email to {to_email}")
        
        # Log successful email sending
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "sent",
            "timestamp": datetime.now(timezone.utc),
            "details": "Password reset confirmation email sent successfully"
        })
        return True
    except smtplib.SMTPRecipientsRefused as e:
        logger.error(f"SMTP Recipients Refused - Confirmation email not sent to {to_email}: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPRecipientsRefused: {str(e)}"
        })
        return False
    except smtplib.SMTPHeloError as e:
        logger.error(f"SMTP HELO Error - Server didn't reply properly: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPHeloError: {str(e)}"
        })
        return False
    except smtplib.SMTPSenderRefused as e:
        logger.error(f"SMTP Sender Refused - From address rejected: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPSenderRefused: {str(e)}"
        })
        return False
    except smtplib.SMTPDataError as e:
        logger.error(f"SMTP Data Error - Unexpected reply: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPDataError: {str(e)}"
        })
        return False
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication Error - Username/password refused: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPAuthenticationError: {str(e)}"
        })
        return False
    except smtplib.SMTPException as e:
        logger.error(f"General SMTP Error: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"SMTPException: {str(e)}"
        })
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending password reset confirmation email to {to_email}: {e}")
        email_logs_collection.insert_one({
            "email": to_email,
            "type": "password_reset_confirmation",
            "status": "failed",
            "timestamp": datetime.now(timezone.utc),
            "details": f"UnexpectedError: {str(e)}"
        })
        return False

# --- Routes: Forgot Password (OTP) ---
@router.get("/forgot-password", response_class=HTMLResponse, name="forgot_password_get")
def forgot_password_get(request: Request, message: str = None, error: str = None):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "message": message, "error": error})

@router.post("/forgot-password", response_class=RedirectResponse)
def forgot_password_post(request: Request, email: EmailStr = Form(...)):
    user = users_collection.find_one({"email": email})
    
    # Check if user exists - if not, show specific error message
    if not user:
        return RedirectResponse(url=f"/forgot-password?error=mail/user+not+exists+Please+create+new+account+to+login", status_code=status.HTTP_303_SEE_OTHER)
    
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
    # Try to send email up to 3 times for better reliability
    for attempt in range(3):
        email_sent = send_otp_email(email, otp)
        if email_sent:
            break
        else:
            logger.warning(f"Email sending attempt {attempt + 1} failed for {email}. Retrying...")
            # Wait a bit before retrying
            time.sleep(1)
    
    # Log the email request
    logger.info(f"OTP requested for email: {email}")

    if not email_sent:
        # Email sending failed after all retries
        return RedirectResponse(url=f"/forgot-password?error=Failed+to+send+email.+Please+try+again+later.+Check+your+spam+junk+folder.", status_code=status.HTTP_303_SEE_OTHER)

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

    # Send password reset confirmation email
    send_password_reset_confirmation_email(doc["email"])

    return RedirectResponse(url="/login?message=Password+reset+success", status_code=status.HTTP_303_SEE_OTHER)