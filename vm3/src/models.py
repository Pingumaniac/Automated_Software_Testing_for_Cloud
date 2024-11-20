# src/models.py

from pydantic import BaseModel, Field
from typing import Optional

class ItemBase(BaseModel):
    name: str = Field(..., example="Sample Item")
    description: Optional[str] = Field(None, example="This is a sample item.")
    price: float = Field(..., example=19.99)
    tax: Optional[float] = Field(None, example=1.50)

class ItemCreate(ItemBase):
    item_id: int = Field(..., example=1)

class ItemUpdate(BaseModel):
    name: Optional[str] = Field(None, example="Updated Item")
    description: Optional[str] = Field(None, example="This is an updated description.")
    price: Optional[float] = Field(None, example=24.99)
    tax: Optional[float] = Field(None, example=2.00)

class Item(ItemBase):
    item_id: int
    id: Optional[str] = Field(None, alias="_id")

    class Config:
        orm_mode = True
