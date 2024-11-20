# src/main.py

from fastapi import FastAPI, HTTPException, Depends
from database import Database
from crud import CRUD
from models import ItemCreate, ItemUpdate, Item
from utils import Utils
import os

class App:
    def __init__(self):
        self.app = FastAPI(title="MongoDB Testing API")
        self.database = Database()
        self.crud = CRUD(self.database)
        self.utils = Utils()
        self.register_events()
        self.register_routes()

    def register_events(self):
        @self.app.on_event("startup")
        def startup_event():
            self.database.connect()
            print("Application startup: Connected to MongoDB.")

        @self.app.on_event("shutdown")
        def shutdown_event():
            self.database.close()
            print("Application shutdown: MongoDB connection closed.")

    def register_routes(self):
        @self.app.post("/items/", response_model=Item)
        async def create_new_item(item: ItemCreate, crud: CRUD = Depends(lambda: self.crud)):
            """
            Create a new item in the database.
            """
            try:
                return crud.create_item(item)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.app.get("/items/{item_id}", response_model=Item)
        async def get_item(item_id: int, crud: CRUD = Depends(lambda: self.crud)):
            """
            Retrieve an item by its ID.
            """
            item = crud.read_item(item_id)
            if item is None:
                raise HTTPException(status_code=404, detail="Item not found")
            return item

        @self.app.put("/items/{item_id}", response_model=Item)
        async def update_existing_item(item_id: int, item: ItemUpdate, crud: CRUD = Depends(lambda: self.crud)):
            """
            Update an existing item.
            """
            updated_item = crud.update_item(item_id, item)
            if updated_item is None:
                raise HTTPException(status_code=404, detail="Item not found or no changes made")
            return updated_item

        @self.app.delete("/items/{item_id}")
        async def delete_existing_item(item_id: int, crud: CRUD = Depends(lambda: self.crud)):
            """
            Delete an item by its ID.
            """
            success = crud.delete_item(item_id)
            if not success:
                raise HTTPException(status_code=404, detail="Item not found")
            return {"detail": "Item deleted successfully"}

        @self.app.get("/metrics/")
        async def get_metrics():
            """
            Retrieve application metrics.
            """
            return self.utils.get_metrics()

    def get_app(self):
        return self.app

# Instantiate and retrieve the FastAPI app
app_instance = App()
app = app_instance.get_app()

if __name__ == "__main__":
    import uvicorn
    api_port = int(os.getenv("API_PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=api_port, reload=True)
