import random
import string
import pymongo
import afl  # AFL instrumentation library
from pymongo.errors import ConnectionFailure
import time


class AFLFuzzer:
    def __init__(self, uri="mongodb://192.168.5.211:27017,192.168.5.25:27017/?replicaSet=rs0", database_name="testdb", collection_name="fuzzdata"):
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
            self.client = pymongo.MongoClient(self.uri)
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

    def fuzz_insert(self):
        """
        Perform an insert operation with random data for fuzzing.
        """
        try:
            document = self.random_document()
            result = self.collection.insert_one(document)
            print(f"Inserted document with ID: {result.inserted_id}")
            return True
        except Exception as e:
            print(f"Error during insert operation: {e}")
            return False

    def fuzz_update(self):
        """
        Perform an update operation with random data for fuzzing.
        """
        try:
            query = {"name": self.random_string(5)}
            update = {"$set": {"age": random.randint(1, 100)}}
            result = self.collection.update_one(query, update)
            print(f"Updated {result.modified_count} document(s)")
            return True
        except Exception as e:
            print(f"Error during update operation: {e}")
            return False

    def fuzz_delete(self):
        """
        Perform a delete operation with random data for fuzzing.
        """
        try:
            query = {"name": self.random_string(5)}
            result = self.collection.delete_one(query)
            print(f"Deleted {result.deleted_count} document(s)")
            return True
        except Exception as e:
            print(f"Error during delete operation: {e}")
            return False

    def fuzz_query(self):
        """
        Perform a query operation with random data for fuzzing.
        """
        try:
            query = {"age": {"$gte": random.randint(1, 100)}}
            result = list(self.collection.find(query))
            print(f"Queried {len(result)} documents matching query {query}")
            return True
        except Exception as e:
            print(f"Error during query operation: {e}")
            return False

    def random_operation(self):
        """
        Perform a random database operation and track metrics.
        """
        operation = random.choice(["insert", "update", "delete", "query"])
        latency, success = 0, False

        if operation == "insert":
            latency, success = self.measure_latency(self.fuzz_insert)
        elif operation == "update":
            latency, success = self.measure_latency(self.fuzz_update)
        elif operation == "delete":
            latency, success = self.measure_latency(self.fuzz_delete)
        elif operation == "query":
            latency, success = self.measure_latency(self.fuzz_query)

        # Record metrics
        self.metrics["operations"][operation] += 1
        self.metrics["latencies"][operation].append(latency)
        if not success:
            self.metrics["failures"][operation] += 1

    def print_metrics(self):
        """
        Print collected metrics after fuzzing.
        """
        print("\n--- AFL Fuzz Testing Metrics ---")
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


def fuzz_operations(fuzzer):
    """
    Perform random MongoDB operations for fuzz testing.
    """
    fuzzer.random_operation()


if __name__ == "__main__":
    # AFL starts fuzzing from here
    fuzzer = AFLFuzzer()
    fuzzer.connect()

    afl.init()  # AFL instrumentation

    # Fuzz until AFL terminates
    while afl.loop(1000):  # AFL loop to keep fuzzing for a set number of iterations
        fuzz_operations(fuzzer)

    fuzzer.print_metrics()
    fuzzer.close()
