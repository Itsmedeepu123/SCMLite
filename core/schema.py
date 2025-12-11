# schema/schema.py

from pydantic import BaseModel, Field, validator
from datetime import date

class Shipments(BaseModel):
    shipmentNumber: str
    route: str
    origin: str
    destination: str
    poNumber: int
    ndcNumber: int
    serialNumber: int
    goodsType: str
    deliveryDate: date
    deliveryNumber: int
    batchId: str
    shipmentDesc: str

    