from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from src.mongo_client import MongoDBClient

app = FastAPI()

# Initialize MongoDB client and connect
db_client = MongoDBClient(uri="mongodb://localhost:27017", database_name="testdb")
db_client.connect()

# Pydantic models for request validation
class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    in_stock: bool

class ItemUpdate(BaseModel):
    description: Optional[str]
    price: Optional[float]
    in_stock: Optional[bool]


@app.post("/items/", response_model=dict)
def create_item(item: Item):
    """Create a new item in the MongoDB collection."""
    try:
        item_dict = item.dict()
        db_client.insert_one("items", item_dict)
        return {"message": "Item created successfully", "item": item_dict}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/items/", response_model=List[dict])
def get_items(name: Optional[str] = None):
    """Retrieve items from MongoDB collection, optionally filter by name."""
    try:
        query = {"name": name} if name else {}
        items = db_client.find("items", query)
        return items
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/items/{name}", response_model=dict)
def update_item(name: str, item: ItemUpdate):
    """Update an existing item by name."""
    try:
        update_data = item.dict(exclude_unset=True)
        result = db_client.update_one("items", {"name": name}, update_data)
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Item not found")
        return {"message": "Item updated successfully", "name": name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/items/{name}", response_model=dict)
def delete_item(name: str):
    """Delete an item by name."""
    try:
        result = db_client.delete_one("items", {"name": name})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Item not found")
        return {"message": "Item deleted successfully", "name": name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
