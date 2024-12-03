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
            "admins": self.db["Admin"],
            "messages": self.db["Messages"],
        }
        self.account_ids = ["pingu", "pinga", "pingi", "robby"]

    def setup_initial_accounts(self):
        """
        Set up four accounts with fixed accountIDs, and create corresponding User and Admin entries.
        """
        account_data = [
            {"accountID": "pingu", "isAdmin": False, "name": "Pingu", "role": None},
            {"accountID": "pinga", "isAdmin": False, "name": "Pinga", "role": None},
            {"accountID": "pingi", "isAdmin": True, "name": "Pingi", "role": "Moderator"},
            {"accountID": "robby", "isAdmin": True, "name": "Robby", "role": "SuperAdmin"},
        ]

        for account in account_data:
            # Insert Account
            self.collections["accounts"].update_one(
                {"accountID": account["accountID"]},
                {
                    "$setOnInsert": {
                        "accountID": account["accountID"],
                        "isAdmin": account["isAdmin"],
                        "created_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow(),
                    }
                },
                upsert=True,
            )
            # Insert User or Admin
            if account["isAdmin"]:
                self.collections["admins"].update_one(
                    {"accountID": account["accountID"]},
                    {
                        "$setOnInsert": {
                            "accountID": account["accountID"],
                            "name": account["name"],
                            "birthday": datetime(1980, 1, 1),
                            "nationality": "Penguinland",
                            "gender": "Other",
                            "ethnicity": "Penguin",
                            "role": account["role"],
                            "created_at": datetime.utcnow(),
                            "updated_at": datetime.utcnow(),
                        }
                    },
                    upsert=True,
                )
            else:
                self.collections["users"].update_one(
                    {"accountID": account["accountID"]},
                    {
                        "$setOnInsert": {
                            "accountID": account["accountID"],
                            "name": account["name"],
                            "birthday": datetime(1990, 1, 1),
                            "nationality": "Penguinland",
                            "gender": "Other",
                            "ethnicity": "Penguin",
                            "created_at": datetime.utcnow(),
                            "updated_at": datetime.utcnow(),
                        }
                    },
                    upsert=True,
                )

    def fuzz_operation(self, data):
        if self.collections["messages"].count_documents({}) >= 300:
            return  # Stop fuzzing after 300 messages

        try:
            fuzz_data = json.loads(data.decode("utf-8", errors="ignore"))
            operation = fuzz_data.get("operation", "unknown")
            if operation == "insert_message":
                self.insert_message(fuzz_data)
            else:
                logger.warning(f"Unrecognized operation: {operation}")
        except Exception as e:
            logger.error(f"Crash detected during fuzzing operation: {e}")

    def insert_message(self, fuzz_data):
        try:
            document = {
                "senderID": fuzz_data.get("senderID", random.choice(self.account_ids[:2])),  # From pingu or pinga
                "receiverID": fuzz_data.get("receiverID", random.choice(self.account_ids[2:])),  # To pingi or robby
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
            logger.error(f"Error inserting message: {e}")

    def generate_metrics(self):
        total_messages = self.collections["messages"].count_documents({})
        logger.info(f"Total messages inserted: {total_messages}")


def fuzz_target(data):
    fuzzer.fuzz_operation(data)


if __name__ == "__main__":
    # MongoDB URI and Database Name
    MONGO_URI = "mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0"
    DB_NAME = "test_db"

    # Initialize MongoFuzzer
    fuzzer = MongoFuzzer(MONGO_URI, DB_NAME)

    # Setup initial accounts, users, and admins
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
                "receiverID": "pingi",
                "content": "Test Message 1",
                "status": "Sent",
                "sent_time": str(datetime.utcnow()),
            },
            {
                "operation": "insert_message",
                "senderID": "pinga",
                "receiverID": "robby",
                "content": "Test Message 2",
                "status": "Delivered",
                "sent_time": str(datetime.utcnow()),
            },
            {
                "operation": "insert_message",
                "senderID": "pingu",
                "receiverID": "robby",
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

    # Generate metrics
    fuzzer.generate_metrics()
