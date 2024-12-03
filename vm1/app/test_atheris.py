# test_atheris.py

import atheris
import sys
import json
import os
from pymongo import MongoClient
from datetime import datetime
import uuid
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger("AtherisFuzzer")


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

    def fuzz_operation(self, data):
        try:
            fuzz_data = json.loads(data.decode("utf-8", errors="ignore"))
            self.metrics["total_operations"] += 1

            operation = fuzz_data.get("operation", "unknown")
            if operation == "insert_account":
                self.insert_account(fuzz_data)
            elif operation == "insert_user":
                self.insert_user(fuzz_data)
            elif operation == "insert_message":
                self.insert_message(fuzz_data)
            else:
                self.metrics["edge_cases"].add(operation)

        except Exception as e:
            self.metrics["crashes"] += 1
            logger.error(f"Crash detected: {e}")

    def insert_account(self, fuzz_data):
        document = {
            "accountID": fuzz_data.get("accountID", str(uuid.uuid4())),
            "isAdmin": fuzz_data.get("isAdmin", False),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["accounts"].insert_one(document)
        self.metrics["code_paths"].add("insert_account")

    def insert_user(self, fuzz_data):
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
        self.metrics["code_paths"].add("insert_user")

    def insert_message(self, fuzz_data):
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
        self.metrics["code_paths"].add("insert_message")

    def generate_metrics(self):
        crash_rate = (
            (self.metrics["crashes"] / self.metrics["total_operations"]) * 100
            if self.metrics["total_operations"] > 0
            else 0
        )
        edge_case_coverage = len(self.metrics["edge_cases"])
        execution_paths_tested = len(self.metrics["code_paths"])

        metrics = {
            "Crash Rate (%)": crash_rate,
            "Edge Case Coverage": edge_case_coverage,
            "Execution Paths Tested": execution_paths_tested,
            "Total Operations": self.metrics["total_operations"],
        }

        # Save metrics to metrics_atheris.json
        with open("metrics_atheris.json", "w") as f:
            json.dump(metrics, f, indent=4)
        logger.info("Metrics saved to metrics_atheris.json")


def fuzz_target(data):
    fuzzer.fuzz_operation(data)


if __name__ == "__main__":
    # MongoDB URI and Database Name
    MONGO_URI = "mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0"
    DB_NAME = "test_db"

    # Prepare Seed Inputs Directory
    INPUT_DIR = "input_dir_atheris"
    if not os.path.exists(INPUT_DIR):
        os.makedirs(INPUT_DIR)

        # Create seed inputs
        seeds = [
            {"operation": "insert_account", "accountID": str(uuid.uuid4()), "isAdmin": False},
            {"operation": "insert_user", "accountID": str(uuid.uuid4()), "name": "User", "gender": "Non-Binary"},
            {"operation": "insert_message", "senderID": str(uuid.uuid4()), "receiverID": str(uuid.uuid4()), "content": "Test Message"},
        ]
        for idx, seed in enumerate(seeds, start=1):
            with open(f"{INPUT_DIR}/seed_{idx}.json", "w") as f:
                json.dump(seed, f)

    # Initialize MongoFuzzer
    fuzzer = MongoFuzzer(MONGO_URI, DB_NAME)

    # Run Atheris
    atheris.Setup(sys.argv, fuzz_target)
    atheris.Fuzz()

    # Generate and save metrics
    fuzzer.generate_metrics()
