import logging
from datetime import datetime

# Third-party imports
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Local imports
from core.database import users_collection, db
from core.auth import get_current_admin_user

logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["Admin"])
templates = Jinja2Templates(directory="templates")

# MongoDB Collection for Email Logs
email_logs_collection = db["email_logs"]

# MongoDB Collection for Ratings
ratings_collection = db["ratings"]

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