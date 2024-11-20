# src/database.py

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os
import logging

class Database:
    def __init__(self):
        self.client = None
        self.db = None
        self.logger = self.setup_logger()

    def setup_logger(self):
        logger = logging.getLogger("Database")
        logger.setLevel(logging.INFO)
        # Create handlers if not already present
        if not logger.handlers:
            c_handler = logging.StreamHandler()
            f_handler = logging.FileHandler("database.log")
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

    def connect(self):
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://192.168.5.211:27017,192.168.5.25:27017/?replicaSet=rs0")
        try:
            self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            # The ismaster command is cheap and does not require auth.
            self.client.admin.command('ismaster')
            self.db = self.client.get_default_database()
            self.logger.info("Connected to MongoDB successfully.")
        except ConnectionFailure as e:
            self.logger.error(f"Could not connect to MongoDB: {e}")
            raise e

    def close(self):
        if self.client:
            self.client.close()
            self.logger.info("MongoDB connection closed.")

    def get_database(self):
        if not self.db:
            self.logger.error("Database not connected.")
            raise ConnectionError("Database not connected.")
        return self.db
