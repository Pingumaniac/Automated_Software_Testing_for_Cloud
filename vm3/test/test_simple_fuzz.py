import random
import string
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

class TestSimpleFuzzing:
    def __init__(self, uri="mongodb://localhost:27017", database_name="testdb", collection_name="fuzzdata"):
        self.uri = uri
        self.database_name = database_name
        self.collection_name = collection_name
        self.client = None
        self.db = None
        self.collection = None

    def connect(self):
        """
        Connect to the MongoDB server and the specified database and collection.
        """
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
            self.collection = self.db[self.collection_name]
            # Test connection
            self.client.admin.command('ping')
            print(f"Connected to MongoDB at {self.uri}")
        except ConnectionFailure as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise

    def random_string(self, length=10):
        """
        Generate a random string of specified length.
        """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for _ in range(length))

    def random_document(self):
        """
        Generate a random document with random fields and values.
        """
        return {
            "name": self.random_string(),
            "age": random.randint(1, 100),
            "email": f"{self.random_string(5)}@example.com",
            "score": random.uniform(0, 100)
        }

    def random_operation(self):
        """
        Perform a random database operation (insert, update, delete, query).
        """
        operation = random.choice(["insert", "update", "delete", "query"])

        if operation == "insert":
            self.insert_random_document()
        elif operation == "update":
            self.update_random_document()
        elif operation == "delete":
            self.delete_random_document()
        elif operation == "query":
            self.query_random_document()

    def insert_random_document(self):
        """
        Insert a randomly generated document into the collection.
        """
        document = self.random_document()
        result = self.collection.insert_one(document)
        print(f"Inserted document with ID: {result.inserted_id}")

    def update_random_document(self):
        """
        Update a random document in the collection by modifying a field.
        """
        document = self.random_document()
        query = {"name": document["name"]}
        update = {"$set": {"age": random.randint(1, 100)}}
        result = self.collection.update_one(query, update)
        print(f"Updated {result.modified_count} document(s)")

    def delete_random_document(self):
        """
        Delete a random document from the collection.
        """
        document = self.random_document()
        query = {"name": document["name"]}
        result = self.collection.delete_one(query)
        print(f"Deleted {result.deleted_count} document(s)")

    def query_random_document(self):
        """
        Query a random document from the collection.
        """
        query = {"age": {"$gte": random.randint(1, 100)}}
        result = self.collection.find(query)
        print(f"Queried {result.count()} documents matching query {query}")

    def fuzz(self, iterations=100):
        """
        Run random operations on the MongoDB collection for a given number of iterations.
        """
        for i in range(iterations):
            print(f"Fuzzing iteration: {i + 1}")
            self.random_operation()

    def close(self):
        """
        Close the MongoDB connection.
        """
        if self.client:
            self.client.close()
            print("MongoDB connection closed.")

if __name__ == "__main__":
    # Set up fuzzer
    fuzzer = TestSimpleFuzzing()
    fuzzer.connect()

    # Run fuzzing for a specified number of iterations
    fuzzer.fuzz(iterations=50)

    # Close connection
    fuzzer.close()
