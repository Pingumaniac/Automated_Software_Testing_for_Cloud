from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

class MongoClientManager:
    def __init__(self, uri="mongodb://localhost:27017", database_name="testdb"):
        self.uri = uri
        self.database_name = database_name
        self.client = None
        self.db = None

    def connect(self):
        """Connect to MongoDB"""
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
        except ConnectionFailure as e:
            raise Exception(f"Could not connect to MongoDB: {e}")

    def insert_one(self, collection_name, document):
        """Insert a single document"""
        return self.db[collection_name].insert_one(document)

    def find(self, collection_name, query):
        """Find documents in a collection"""
        return list(self.db[collection_name].find(query))

    def update_one(self, collection_name, query, update):
        """Update a single document"""
        return self.db[collection_name].update_one(query, {"$set": update})

    def delete_one(self, collection_name, query):
        """Delete a single document"""
        return self.db[collection_name].delete_one(query)
