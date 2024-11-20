import time
from pymongo import MongoClient


class MongoDBPerformanceTest:
    def __init__(self, uri="mongodb://192.168.5.211:27017,192.168.5.25:27017/?replicaSet=rs0", database_name="performance_db", collection_name="performance_collection"):
        self.uri = uri
        self.database_name = database_name
        self.collection_name = collection_name
        self.client = None
        self.db = None
        self.collection = None

    def connect(self):
        """
        Connect to MongoDB instance.
        """
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
            self.collection = self.db[self.collection_name]
            print(f"Connected to MongoDB at {self.uri}")
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise

    def insert_performance(self, num_docs=1000):
        """
        Measure performance of bulk insert operations.
        """
        docs = [{"name": f"user_{i}", "value": i} for i in range(num_docs)]
        start_time = time.time()
        self.collection.insert_many(docs)
        elapsed_time = time.time() - start_time
        print(f"Inserted {num_docs} documents in {elapsed_time:.2f} seconds.")
        return elapsed_time

    def read_performance(self, num_queries=1000):
        """
        Measure performance of read operations.
        """
        start_time = time.time()
        for i in range(num_queries):
            self.collection.find_one({"name": f"user_{i}"})
        elapsed_time = time.time() - start_time
        print(f"Queried {num_queries} documents in {elapsed_time:.2f} seconds.")
        return elapsed_time

    def update_performance(self, num_updates=1000):
        """
        Measure performance of update operations.
        """
        start_time = time.time()
        for i in range(num_updates):
            self.collection.update_one({"name": f"user_{i}"}, {"$set": {"value": i + 1}})
        elapsed_time = time.time() - start_time
        print(f"Updated {num_updates} documents in {elapsed_time:.2f} seconds.")
        return elapsed_time

    def delete_performance(self, num_deletes=1000):
        """
        Measure performance of delete operations.
        """
        start_time = time.time()
        for i in range(num_deletes):
            self.collection.delete_one({"name": f"user_{i}"})
        elapsed_time = time.time() - start_time
        print(f"Deleted {num_deletes} documents in {elapsed_time:.2f} seconds.")
        return elapsed_time

    def run_all_tests(self, num_docs=1000):
        """
        Execute all performance tests.
        """
        print("Starting MongoDB Performance Tests...")
        results = {
            "insert_time": self.insert_performance(num_docs),
            "read_time": self.read_performance(num_docs),
            "update_time": self.update_performance(num_docs),
            "delete_time": self.delete_performance(num_docs),
        }
        print("\n--- Performance Test Summary ---")
        for operation, elapsed_time in results.items():
            print(f"{operation.replace('_', ' ').capitalize()}: {elapsed_time:.2f} seconds")
        return results


if __name__ == "__main__":
    # Initialize and connect to MongoDB
    performance_test = MongoDBPerformanceTest(uri="mongodb://192.168.5.211:27017,192.168.5.25:27017/?replicaSet=rs0", database_name="performance_db")
    performance_test.connect()

    # Run performance tests with a default of 1000 documents
    performance_test.run_all_tests(num_docs=1000)
