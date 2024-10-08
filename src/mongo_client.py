from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

class MongoDBClient:
    def __init__(self, uri="mongodb://localhost:27017", database_name="testdb"):
        """
        Initialize the MongoDB client with a given URI and database name.
        """
        self.uri = uri
        self.database_name = database_name
        self.client = None
        self.db = None

    def connect(self):
        """
        Connect to the MongoDB server and select the database.
        """
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
            # Test connection
            self.client.admin.command('ping')
            print(f"Connected to MongoDB at {self.uri}")
        except ConnectionFailure as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise

    def insert_one(self, collection_name, document):
        """
        Insert a single document into a collection.
        """
        collection = self.db[collection_name]
        result = collection.insert_one(document)
        return result.inserted_id

    def find(self, collection_name, query):
        """
        Find documents in a collection based on a query.
        """
        collection = self.db[collection_name]
        return list(collection.find(query))

    def update_one(self, collection_name, query, update):
        """
        Update a single document in a collection.
        """
        collection = self.db[collection_name]
        result = collection.update_one(query, {"$set": update})
        return result.modified_count

    def delete_one(self, collection_name, query):
        """
        Delete a single document from a collection.
        """
        collection = self.db[collection_name]
        result = collection.delete_one(query)
        return result.deleted_count

    def close(self):
        """
        Close the connection to the MongoDB server.
        """
        if self.client:
            self.client.close()
            print("MongoDB connection closed.")
