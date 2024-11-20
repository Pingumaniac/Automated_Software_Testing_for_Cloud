# src/crud.py

from models import Item, ItemCreate, ItemUpdate
from database import Database
from bson.objectid import ObjectId
import logging

class CRUD:
    def __init__(self, database: Database):
        self.db = database.get_database()
        self.collection = self.db["items"]
        self.logger = self.setup_logger()

    def setup_logger(self):
        logger = logging.getLogger("CRUD")
        logger.setLevel(logging.INFO)
        # Create handlers if not already present
        if not logger.handlers:
            c_handler = logging.StreamHandler()
            f_handler = logging.FileHandler("crud.log")
            c_handler.setLevel(logging.INFO)
            f_handler.setLevel(logging.INFO)
            # Create formatters and add to handlers
            c_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            f_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            c_handler.setFormatter(c_format)
            f_handler.setFormatter(f_format)
            # Add handlers to the logger
            logger.addHandler(c_handler)
            logger.addHandler(f_handler)
        return logger

    def create_item(self, item: ItemCreate) -> Item:
        try:
            item_dict = item.dict()
            result = self.collection.insert_one(item_dict)
            item_dict["_id"] = str(result.inserted_id)
            self.logger.info(f"Created item with ID: {result.inserted_id}")
            return Item(**item_dict)
        except Exception as e:
            self.logger.error(f"Error creating item: {e}")
            raise e

    def read_item(self, item_id: int) -> Item:
        try:
            item = self.collection.find_one({"item_id": item_id})
            if item:
                item["_id"] = str(item["_id"])
                self.logger.info(f"Read item with ID: {item_id}")
                return Item(**item)
            self.logger.warning(f"Item with ID {item_id} not found.")
            return None
        except Exception as e:
            self.logger.error(f"Error reading item {item_id}: {e}")
            raise e

    def update_item(self, item_id: int, item: ItemUpdate) -> Item:
        try:
            update_data = {k: v for k, v in item.dict().items() if v is not None}
            if not update_data:
                self.logger.warning("No update data provided.")
                return None
            result = self.collection.update_one({"item_id": item_id}, {"$set": update_data})
            if result.modified_count == 1:
                self.logger.info(f"Updated item with ID: {item_id}")
                return self.read_item(item_id)
            self.logger.warning(f"No changes made to item with ID: {item_id}")
            return None
        except Exception as e:
            self.logger.error(f"Error updating item {item_id}: {e}")
            raise e

    def delete_item(self, item_id: int) -> bool:
        try:
            result = self.collection.delete_one({"item_id": item_id})
            if result.deleted_count == 1:
                self.logger.info(f"Deleted item with ID: {item_id}")
                return True
            self.logger.warning(f"Item with ID {item_id} not found for deletion.")
            return False
        except Exception as e:
            self.logger.error(f"Error deleting item {item_id}: {e}")
            raise e
