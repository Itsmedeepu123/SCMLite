import logging
from datetime import datetime, timedelta
from typing import Optional

# Third-party imports
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import EmailStr
from jose import JWTError

# Local imports
from core.database import users_collection, db
from core.auth import (
    verify_password, get_password_hash, create_access_token,
    decode_token, get_required_current_user
)
from core.config import ACCESS_TOKEN_EXPIRE_MINUTES

logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["API"])

# --- Configuration & Constants ---
ACCESS_TOKEN_EXPIRE_MINUTES = int(ACCESS_TOKEN_EXPIRE_MINUTES)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

# MongoDB Collection for Ratings
ratings_collection = db["ratings"]

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

@router.post("/api/login", response_class=JSONResponse)
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