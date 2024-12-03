# test_atheris.py

import atheris
import sys
import json
import os
from pymongo import MongoClient
from datetime import datetime
import logging
import random

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
        self.account_ids = ["pingu", "pinga", "robby", "pingi"]
        self.metrics = {
            "total_operations": 0,
            "crashes": 0,
            "edge_cases": set(),
        }

    def setup_initial_accounts(self):
        """
        Set up two accounts for users and two accounts for senders with fixed accountIDs.
        """
        for accountID in self.account_ids:
            self.collections["accounts"].update_one(
                {"accountID": accountID},
                {
                    "$setOnInsert": {
                        "accountID": accountID,
                        "isAdmin": False,
                        "created_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow(),
                    }
                },
                upsert=True,
            )
            logger.info(f"Ensured account exists: {accountID}")

    def fuzz_operation(self, data):
        if self.metrics["total_operations"] >= 300:
            return  # Stop fuzzing after 300 operations

        try:
            fuzz_data = json.loads(data.decode("utf-8", errors="ignore"))
            self.metrics["total_operations"] += 1

            operation = fuzz_data.get("operation", "unknown")
            if operation == "insert_message":
                self.insert_message(fuzz_data)
            else:
                self.metrics["edge_cases"].add(operation)

        except Exception as e:
            self.metrics["crashes"] += 1
            logger.error(f"Crash detected during fuzzing operation: {e}")

    def insert_message(self, fuzz_data):
        try:
            document = {
                "senderID": fuzz_data.get("senderID", random.choice(self.account_ids[:2])),  # From pingu or pinga
                "receiverID": fuzz_data.get("receiverID", random.choice(self.account_ids[2:])),  # To robby or pingi
                "content": fuzz_data.get("content", "Hello, World!"),
                "sent_time": fuzz_data.get("sent_time", datetime.utcnow()),
                "read_time": fuzz_data.get("read_time", None),
                "status": fuzz_data.get("status", random.choice(["Sent", "Delivered", "Read"])),
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
            self.collections["messages"].insert_one(document)
            logger.info(f"Successfully inserted message: {document}")
        except Exception as e:
            self.metrics["crashes"] += 1
            logger.error(f"Error inserting message: {e}")

    def generate_metrics(self):
        crash_rate = (
            (self.metrics["crashes"] / self.metrics["total_operations"]) * 100
            if self.metrics["total_operations"] > 0
            else 0
        )
        metrics = {
            "Total Operations": self.metrics["total_operations"],
            "Crashes": self.metrics["crashes"],
            "Crash Rate (%)": crash_rate,
            "Edge Case Coverage": len(self.metrics["edge_cases"]),
        }

        # Save metrics to metrics_atheris.json
        with open("metrics_atheris.json", "w") as f:
            json.dump(metrics, f, indent=4)
        logger.info("Metrics saved to metrics_atheris.json")
        logger.info(json.dumps(metrics, indent=4))


def fuzz_target(data):
    fuzzer.fuzz_operation(data)


if __name__ == "__main__":
    # MongoDB URI and Database Name
    MONGO_URI = "mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0"
    DB_NAME = "test_db"

    # Initialize MongoFuzzer
    fuzzer = MongoFuzzer(MONGO_URI, DB_NAME)

    # Setup initial accounts
    fuzzer.setup_initial_accounts()

    # Prepare Seed Inputs Directory
    INPUT_DIR = "input_dir_atheris"
    if not os.path.exists(INPUT_DIR):
        os.makedirs(INPUT_DIR)

        # Create seed inputs
        seeds = [
            {
                "operation": "insert_message",
                "senderID": "pingu",
                "receiverID": "robby",
                "content": "Test Message 1",
                "status": "Sent",
                "sent_time": str(datetime.utcnow()),
            },
            {
                "operation": "insert_message",
                "senderID": "pinga",
                "receiverID": "pingi",
                "content": "Test Message 2",
                "status": "Delivered",
                "sent_time": str(datetime.utcnow()),
            },
            {
                "operation": "insert_message",
                "senderID": "pingu",
                "receiverID": "pingi",
                "content": "Edge case test",
                "status": "Read",
                "sent_time": str(datetime.utcnow()),
                "read_time": str(datetime.utcnow()),
            },
        ]
        for idx, seed in enumerate(seeds, start=1):
            with open(f"{INPUT_DIR}/seed_{idx}.json", "w") as f:
                json.dump(seed, f)

    # Run Atheris
    atheris.Setup(sys.argv, fuzz_target)
    atheris.Fuzz()

    # Generate and save metrics
    fuzzer.generate_metrics()
