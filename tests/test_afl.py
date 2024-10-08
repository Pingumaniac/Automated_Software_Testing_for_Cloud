import random
import string
import pymongo
import afl  # AFL instrumentation library
from pymongo.errors import ConnectionFailure

class AFLFuzzer:
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
            self.client = pymongo.MongoClient(self.uri)
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

    def fuzz_insert(self):
        """
        Perform an insert operation with random data for fuzzing.
        """
        try:
            document = self.random_document()
            result = self.collection.insert_one(document)
            print(f"Inserted document with ID: {result.inserted_id}")
        except Exception as e:
            print(f"Error during insert operation: {e}")

    def fuzz_update(self):
        """
        Perform an update operation with random data for fuzzing.
        """
        try:
            document = self.random_document()
            query = {"name": document["name"]}
            update = {"$set": {"age": random.randint(1, 100)}}
            result = self.collection.update_one(query, update)
            print(f"Updated {result.modified_count} document(s)")
        except Exception as e:
            print(f"Error during update operation: {e}")

    def fuzz_delete(self):
        """
        Perform a delete operation with random data for fuzzing.
        """
        try:
            document = self.random_document()
            query = {"name": document["name"]}
            result = self.collection.delete_one(query)
            print(f"Deleted {result.deleted_count} document(s)")
        except Exception as e:
            print(f"Error during delete operation: {e}")

    def fuzz_query(self):
        """
        Perform a query operation with random data for fuzzing.
        """
        try:
            query = {"age": {"$gte": random.randint(1, 100)}}
            result = self.collection.find(query)
            print(f"Queried documents matching query {query}")
        except Exception as e:
            print(f"Error during query operation: {e}")

    def close(self):
        """
        Close the MongoDB connection.
        """
        if self.client:
            self.client.close()
            print("MongoDB connection closed.")

def fuzz_operations(fuzzer):
    """
    Perform random MongoDB operations for fuzz testing.
    """
    operation = random.choice(["insert", "update", "delete", "query"])

    if operation == "insert":
        fuzzer.fuzz_insert()
    elif operation == "update":
        fuzzer.fuzz_update()
    elif operation == "delete":
        fuzzer.fuzz_delete()
    elif operation == "query":
        fuzzer.fuzz_query()

if __name__ == "__main__":
    # AFL starts fuzzing from here
    fuzzer = AFLFuzzer()
    fuzzer.connect()

    afl.init()  # AFL++ instrumentation

    # Fuzz until AFL++ terminates
    while afl.loop(1000):  # AFL++ loop to keep fuzzing for a set number of iterations
        fuzz_operations(fuzzer)

    fuzzer.close()
