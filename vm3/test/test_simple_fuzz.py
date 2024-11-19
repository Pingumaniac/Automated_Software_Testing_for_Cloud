import random
import string
import time
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
        self.metrics = {
            "operations": {"insert": 0, "update": 0, "delete": 0, "query": 0},
            "failures": {"insert": 0, "update": 0, "delete": 0, "query": 0},
            "latencies": {"insert": [], "update": [], "delete": [], "query": []},
        }

    def connect(self):
        """
        Connect to the MongoDB server and the specified database and collection.
        """
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
            self.collection = self.db[self.collection_name]
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

    def measure_latency(self, func, *args):
        """
        Measure the latency of a given function.
        """
        start_time = time.time()
        success = func(*args)
        latency = (time.time() - start_time) * 1000  # Convert to milliseconds
        return latency, success

    def insert_random_document(self):
        """
        Insert a randomly generated document into the collection.
        """
        try:
            document = self.random_document()
            result = self.collection.insert_one(document)
            print(f"Inserted document with ID: {result.inserted_id}")
            return True
        except Exception as e:
            print(f"Insert failed: {e}")
            return False

    def update_random_document(self):
        """
        Update a random document in the collection by modifying a field.
        """
        try:
            query = {"name": self.random_string(5)}
            update = {"$set": {"age": random.randint(1, 100)}}
            result = self.collection.update_one(query, update)
            print(f"Updated {result.modified_count} document(s)")
            return True
        except Exception as e:
            print(f"Update failed: {e}")
            return False

    def delete_random_document(self):
        """
        Delete a random document from the collection.
        """
        try:
            query = {"name": self.random_string(5)}
            result = self.collection.delete_one(query)
            print(f"Deleted {result.deleted_count} document(s)")
            return True
        except Exception as e:
            print(f"Delete failed: {e}")
            return False

    def query_random_document(self):
        """
        Query a random document from the collection.
        """
        try:
            query = {"age": {"$gte": random.randint(1, 100)}}
            result = list(self.collection.find(query))
            print(f"Queried {len(result)} documents matching query {query}")
            return True
        except Exception as e:
            print(f"Query failed: {e}")
            return False

    def random_operation(self):
        """
        Perform a random database operation (insert, update, delete, query).
        """
        operation = random.choice(["insert", "update", "delete", "query"])
        latency, success = 0, False

        if operation == "insert":
            latency, success = self.measure_latency(self.insert_random_document)
        elif operation == "update":
            latency, success = self.measure_latency(self.update_random_document)
        elif operation == "delete":
            latency, success = self.measure_latency(self.delete_random_document)
        elif operation == "query":
            latency, success = self.measure_latency(self.query_random_document)

        # Record metrics
        self.metrics["operations"][operation] += 1
        self.metrics["latencies"][operation].append(latency)
        if not success:
            self.metrics["failures"][operation] += 1

    def fuzz(self, iterations=100):
        """
        Run random operations on the MongoDB collection for a given number of iterations.
        """
        for i in range(iterations):
            print(f"Fuzzing iteration: {i + 1}")
            self.random_operation()
        self.print_metrics()

    def print_metrics(self):
        """
        Print collected metrics.
        """
        print("\n--- Fuzz Testing Metrics ---")
        for operation, count in self.metrics["operations"].items():
            avg_latency = (
                sum(self.metrics["latencies"][operation]) / len(self.metrics["latencies"][operation])
                if self.metrics["latencies"][operation] else 0
            )
            print(
                f"{operation.capitalize()} - Count: {count}, "
                f"Failures: {self.metrics['failures'][operation]}, "
                f"Avg Latency: {avg_latency:.2f} ms"
            )

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
