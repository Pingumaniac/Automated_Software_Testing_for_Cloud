from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

class MongoClientManager:
    def __init__(self, uri="mongodb://192.168.5.211:27017,192.168.5.68:27017,192.168.5.25:27017/?replicaSet=rs0", database_name="testdb"):
        """
        Initializes the MongoClientManager with a connection URI for the MongoDB replica set
        and the specified database name.
        """
        self.uri = uri
        self.database_name = database_name
        self.client = None
        self.db = None

    def connect(self):
        """Connect to the MongoDB replica set."""
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
            print("Connected to MongoDB replica set.")
        except ConnectionFailure as e:
            raise Exception(f"Could not connect to MongoDB: {e}")

    def insert_one(self, collection_name, document):
        """Insert a single document into the specified collection."""
        return self.db[collection_name].insert_one(document)

    def find(self, collection_name, query):
        """Find documents in the specified collection that match the query."""
        return list(self.db[collection_name].find(query))

    def update_one(self, collection_name, query, update):
        """Update a single document in the specified collection."""
        return self.db[collection_name].update_one(query, {"$set": update})

    def delete_one(self, collection_name, query):
        """Delete a single document in the specified collection."""
        return self.db[collection_name].delete_one(query)
