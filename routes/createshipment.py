# app/routers/shipment.py

from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime
from pymongo import DESCENDING
from pydantic import ValidationError
from fastapi import status
from core.database import shipments_collection
from core.auth import get_required_current_user, get_current_admin_user
from core.schema import Shipments


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def generate_unique_shipment_number():
    """
    Generate a unique shipment number in the format SNXXX (e.g., SN001, SN002, etc.)
    This function ensures uniqueness by checking against existing shipment numbers
    and retrying if a collision occurs.
    """
    # Get the highest existing shipment number
    last_shipment = shipments_collection.find_one(sort=[("shipmentNumber", DESCENDING)])
    
    if last_shipment and "shipmentNumber" in last_shipment:
        last_id = last_shipment["shipmentNumber"]
        # Handle both old (exfscm) and new (SN) formats
        if last_id.startswith("SN"):
            # New format: SN001, SN002, etc.
            try:
                num_part = int(last_id.replace("SN", ""))
                new_id = f"SN{num_part+1:03}"
            except ValueError:
                # If we can't parse the number part, fallback to SN001
                new_id = "SN001"
        elif last_id.startswith("exfscm"):
            # Old format: exfscm01, exfscm02, etc.
            try:
                num_part = int(last_id.replace("exfscm", ""))
                new_id = f"SN{num_part+1:03}"
            except ValueError:
                # If we can't parse the number part, fallback to SN001
                new_id = "SN001"
        else:
            # Fallback for any other format
            new_id = "SN001"
    else:
        new_id = "SN001"
    
    # Check if this shipment number already exists (in case of concurrent creation)
    existing_shipment = shipments_collection.find_one({"shipmentNumber": new_id})
    if not existing_shipment:
        return new_id
        
    # If the generated number already exists, find the next available number
    max_attempts = 1000  # Prevent infinite loops
    for attempt in range(max_attempts):
        # Extract the numeric part and increment
        try:
            num_part = int(new_id.replace("SN", ""))
            new_id = f"SN{num_part+1:03}"
        except ValueError:
            # If we can't parse, use timestamp as fallback
            timestamp = int(datetime.utcnow().timestamp()) % 1000  # Keep it 3 digits
            new_id = f"SN{timestamp:03}"
            
        # Check if this shipment number already exists
        existing_shipment = shipments_collection.find_one({"shipmentNumber": new_id})
        if not existing_shipment:
            return new_id
            
    # If we've tried 1000 times and still getting collisions, use timestamp-based approach
    timestamp = int(datetime.utcnow().timestamp()) % 1000  # Keep it 3 digits
    return f"SN{timestamp:03}"


def validate_shipment_number_format(shipment_number: str) -> bool:
    """
    Validate that the shipment number follows the required format (SNXXX)
    """
    if not shipment_number.startswith("SN"):
        return False
    if len(shipment_number) != 5:
        return False
    try:
        int(shipment_number[2:])
        return True
    except ValueError:
        return False


@router.get("/create-shipment", response_class=HTMLResponse)
async def get_create_shipment_form(request: Request, current_user: dict = Depends(get_required_current_user)):
    new_id = generate_unique_shipment_number()
    success_message = request.query_params.get("success")
    error_message = request.query_params.get("error")
    current_date = datetime.now().strftime('%Y-%m-%d')  #  generate current date in HTML5 format

    return templates.TemplateResponse("create_shipment.html", {
        "request": request,
        "shipment_id": new_id,
        "success": success_message,
        "error": error_message,
        "current_date": current_date  #  pass to template
    })


@router.post("/create-shipment")
async def create_shipment(request: Request,
    shipmentNumber: str = Form(...),
    route: str = Form(...),
    origin: str = Form(...),
    destination: str = Form(...),
    poNumber: int = Form(...),
    ndcNumber: int = Form(...),
    serialNumber: int = Form(...),
    goodsType: str = Form(...),
    deliveryDate: str = Form(...),
    deliveryNumber: int = Form(...),
    batchId: str = Form(...),
    shipmentDesc: str = Form(...),
    current_user: dict = Depends(get_required_current_user)
):
    # Validate shipment number format
    if not validate_shipment_number_format(shipmentNumber):
        return RedirectResponse(
            url=f"/create-shipment?error=Invalid shipment number format. Expected format: SNXXX",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Validate that the shipment number is unique
    existing_shipment = shipments_collection.find_one({"shipmentNumber": shipmentNumber})
    if existing_shipment:
        return RedirectResponse(
            url=f"/create-shipment?error=A shipment with this number already exists. Please try again.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Try to create a Pydantic model for validation
    try:
        shipment_obj = Shipments(
            shipmentNumber=shipmentNumber,
            route=route,
            origin=origin,
            destination=destination,
            poNumber=poNumber,
            ndcNumber=ndcNumber,
            serialNumber=serialNumber,
            goodsType=goodsType,
            deliveryDate=datetime.strptime(deliveryDate, "%Y-%m-%d").date(),
            deliveryNumber=deliveryNumber,
            batchId=batchId,
            shipmentDesc=shipmentDesc
        )
    except ValueError as ve:
        # This can catch int casting errors or date parsing
        return RedirectResponse(
            url=f"/create-shipment?error=Invalid%20input:%20{ve}",
            status_code=status.HTTP_303_SEE_OTHER
        )
    except ValidationError as e:
        # Pydantic validation errors
        # Join all error messages into one string to send back
        
        errors = "; ".join([err['msg'] for err in e.errors()])
        return RedirectResponse(
            url=f"/create-shipment?error=Validation%20error:%20{errors}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Now, if all good, insert data to MongoDB
    shipment_data = shipment_obj.dict()
    shipment_data["created_at"] = datetime.utcnow()
    shipment_data["expected_delivery_date"] = shipment_data.pop("deliveryDate").strftime("%Y-%m-%d")  # keep same format for MongoDB
    shipment_data["created_by"] = current_user.get("name", "unknown")
    shipments_collection.insert_one(shipment_data)

    return RedirectResponse(
        url="/create-shipment?success=Shipment%20created%20successfully",
        status_code=status.HTTP_303_SEE_OTHER
    )