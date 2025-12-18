import os
import logging
from datetime import datetime, timezone

# Third-party imports
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Local imports
from core.database import users_collection, shipments_collection
from core.auth import get_required_current_user

# Load Environment
load_dotenv()
logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["User Profile"])
templates = Jinja2Templates(directory="templates")

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

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, current_user: dict = Depends(get_required_current_user)):
    if current_user.get("role") == "admin":
        return RedirectResponse(url="/admin-dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "message": request.query_params.get("message")
    })