import atheris
import sys
import json
from pymongo import MongoClient
from datetime import datetime
import uuid
import logging


class MongoFuzzer:
    def __init__(self, uri, db_name):
        self.client = MongoClient(uri)
        self.db = self.client[db_name]
        self.collections = {
            "accounts": self.db["Account"],
            "users": self.db["User"],
            "messages": self.db["Messages"],
        }
        self.metrics = {
            "total_operations": 0,
            "crashes": 0,
            "edge_cases": set(),
            "code_paths": set(),
        }
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
        self.logger = logging.getLogger("MongoFuzzer")

    def log_metric(self, metric_name, value):
        self.logger.info(f"{metric_name}: {value}")

    def perform_operation(self, data):
        """
        Perform MongoDB operations based on fuzzed data.
        """
        try:
            fuzz_data = json.loads(data.decode("utf-8", errors="ignore"))
            self.metrics["total_operations"] += 1

            # Randomly choose operations
            if fuzz_data.get("operation") == "insert_account":
                self.insert_account(fuzz_data)
            elif fuzz_data.get("operation") == "insert_user":
                self.insert_user(fuzz_data)
            elif fuzz_data.get("operation") == "insert_message":
                self.insert_message(fuzz_data)
            else:
                self.track_edge_case(fuzz_data.get("operation", "unknown"))
        except Exception as e:
            self.track_crash(e)

    def insert_account(self, fuzz_data):
        """
        Insert a document into the Account collection.
        """
        document = {
            "accountID": fuzz_data.get("accountID", str(uuid.uuid4())),
            "isAdmin": fuzz_data.get("isAdmin", False),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["accounts"].insert_one(document)
        self.track_execution_path("insert_account")

    def insert_user(self, fuzz_data):
        """
        Insert a document into the User collection.
        """
        document = {
            "accountID": fuzz_data.get("accountID", str(uuid.uuid4())),
            "name": fuzz_data.get("name", "User"),
            "birthday": fuzz_data.get("birthday", "1990-01-01"),
            "nationality": fuzz_data.get("nationality", "Unknown"),
            "gender": fuzz_data.get("gender", "Unknown"),
            "ethnicity": fuzz_data.get("ethnicity", "Unknown"),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["users"].insert_one(document)
        self.track_execution_path("insert_user")

    def insert_message(self, fuzz_data):
        """
        Insert a document into the Messages collection.
        """
        document = {
            "senderID": fuzz_data.get("senderID", str(uuid.uuid4())),
            "receiverID": fuzz_data.get("receiverID", str(uuid.uuid4())),
            "content": fuzz_data.get("content", ""),
            "sent_time": datetime.utcnow(),
            "status": fuzz_data.get("status", "Sent"),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["messages"].insert_one(document)
        self.track_execution_path("insert_message")

    # Metric Tracking Functions
    def track_crash(self, exception):
        """
        Track a crash and log details.
        """
        self.metrics["crashes"] += 1
        self.logger.error(f"Crash detected: {exception}")

    def track_edge_case(self, edge_case):
        """
        Track an edge case encountered during fuzzing.
        """
        self.metrics["edge_cases"].add(edge_case)

    def track_execution_path(self, path_name):
        """
        Track the execution path taken during fuzzing.
        """
        self.metrics["code_paths"].add(path_name)

    # Metric Calculation Functions
    def calculate_crash_rate(self):
        """
        Calculate the crash rate as a percentage of total operations.
        """
        crash_rate = (
            (self.metrics["crashes"] / self.metrics["total_operations"]) * 100
            if self.metrics["total_operations"] > 0
            else 0
        )
        self.log_metric("4_1_1_Crash Rate (%)", crash_rate)

    def calculate_edge_case_coverage(self):
        """
        Calculate the number of unique edge cases encountered.
        """
        edge_case_coverage = len(self.metrics["edge_cases"])
        self.log_metric("4_2_1_Edge Case Coverage", edge_case_coverage)

    def calculate_execution_paths_tested(self):
        """
        Calculate the number of unique execution paths tested.
        """
        execution_paths = len(self.metrics["code_paths"])
        self.log_metric("4_2_2_Execution Paths Tested", execution_paths)

    def generate_metrics(self):
        """
        Generate and log all metrics.
        """
        self.calculate_crash_rate()
        self.calculate_edge_case_coverage()
        self.calculate_execution_paths_tested()


def fuzz_target(data):
    """
    Atheris fuzz target function.
    """
    fuzzer.perform_operation(data)


if __name__ == "__main__":
    # MongoDB URI and Database Name
    MONGO_URI = "mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0"
    DB_NAME = "test_db"

    # Initialize MongoFuzzer
    fuzzer = MongoFuzzer(MONGO_URI, DB_NAME)

    # Run Atheris
    atheris.Setup(sys.argv, fuzz_target)
    atheris.Fuzz()

    # Output metrics after fuzzing
    fuzzer.generate_metrics()
