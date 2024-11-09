import time
import pymongo
from pymongo import MongoClient
from statistics import mean

class MongoDBBenchmark:
    def __init__(self, uri="mongodb://localhost:27017", database_name="benchmarkdb", collection_name="benchmark_collection"):
        self.uri = uri
        self.database_name = database_name
        self.collection_name = collection_name
        self.client = None
        self.db = None
        self.collection = None

    def connect(self):
        """ Connect to MongoDB instance """
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.database_name]
            self.collection = self.db[self.collection_name]
            print(f"Connected to MongoDB at {self.uri}")
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            raise

    def insert_benchmark(self, num_docs=1000):
        """ Benchmark the insertion of documents """
        docs = [{"name": f"user_{i}", "value": i} for i in range(num_docs)]
        start_time = time.time()
        self.collection.insert_many(docs)
        end_time = time.time()
        return end_time - start_time

    def read_benchmark(self, num_queries=1000):
        """ Benchmark reading documents """
        start_time = time.time()
        for i in range(num_queries):
            self.collection.find_one({"name": f"user_{i}"})
        end_time = time.time()
        return end_time - start_time

    def update_benchmark(self, num_updates=1000):
        """ Benchmark updating documents """
        start_time = time.time()
        for i in range(num_updates):
            self.collection.update_one({"name": f"user_{i}"}, {"$set": {"value": i + 1}})
        end_time = time.time()
        return end_time - start_time

    def delete_benchmark(self, num_deletes=1000):
        """ Benchmark deleting documents """
        start_time = time.time()
        for i in range(num_deletes):
            self.collection.delete_one({"name": f"user_{i}"})
        end_time = time.time()
        return end_time - start_time

    def run_all_benchmarks(self, num_docs=1000):
        """ Run all CRUD operation benchmarks """
        print("Starting MongoDB Benchmarks...")

        # Run insert benchmark
        insert_time = self.insert_benchmark(num_docs)
        print(f"Insert {num_docs} documents: {insert_time:.2f} seconds")

        # Run read benchmark
        read_time = self.read_benchmark(num_docs)
        print(f"Read {num_docs} documents: {read_time:.2f} seconds")

        # Run update benchmark
        update_time = self.update_benchmark(num_docs)
        print(f"Update {num_docs} documents: {update_time:.2f} seconds")

        # Run delete benchmark
        delete_time = self.delete_benchmark(num_docs)
        print(f"Delete {num_docs} documents: {delete_time:.2f} seconds")

        # Summary
        print("\nBenchmark Summary:")
        print(f"Insertion Time: {insert_time:.2f} seconds")
        print(f"Read Time: {read_time:.2f} seconds")
        print(f"Update Time: {update_time:.2f} seconds")
        print(f"Delete Time: {delete_time:.2f} seconds")


if __name__ == "__main__":
    # Set up MongoDB benchmark
    benchmark = MongoDBBenchmark(uri="mongodb://localhost:27017", database_name="benchmarkdb")
    benchmark.connect()

    # Run benchmarks with 1000 documents as a default
    benchmark.run_all_benchmarks(num_docs=1000)
