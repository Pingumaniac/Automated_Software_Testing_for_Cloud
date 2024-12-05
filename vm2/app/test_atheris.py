# test_atheris.py

import atheris
import sys
import json
import os
from pymongo import MongoClient
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger("AtherisFuzzer")

# Global iteration count and max iterations
iteration_count = 0
MAX_ITERATIONS = 5000

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
        self.metrics = {
            "total_operations": 0,
            "crashes": 0,
            "edge_cases": set(),
            "code_paths": set(),
        }

    def initialize_data(self):
        """
        Populate initial data for accounts, users, and admins.
        """
        self.insert_account("pingu", is_admin=False)
        self.insert_account("pinga", is_admin=False)
        self.insert_account("pingi", is_admin=True)
        self.insert_account("robby", is_admin=True)

        self.insert_user("pingu", "Pingu", "1990-01-01", "Antarctican", "Male", "Penguin")
        self.insert_user("pinga", "Pinga", "1995-05-01", "Antarctican", "Female", "Penguin")
        self.insert_admin(
            "pingi", "Pingi", "1985-12-01", "Antarctican", "Male", "Penguin", "SuperAdmin"
        )
        self.insert_admin(
            "robby", "Robby", "1980-03-15", "Antarctican", "Male", "Penguin", "Moderator"
        )

    def fuzz_operation(self, data):
        """
        Process fuzzing input, modify the message content, and track metrics.
        """
        global iteration_count
        try:
            if iteration_count >= MAX_ITERATIONS:
                # Generate metrics and exit
                logger.info("Reached maximum iterations. Generating final metrics.")
                self.generate_metrics()
                sys.exit("Program terminated after reaching 5000 iterations.")

            # Decode and process fuzzing input
            fuzz_content = data.decode("utf-8", errors="ignore")

            # Simulate code path and edge case tracking
            self.metrics["total_operations"] += 1
            if fuzz_content.strip() == "":
                self.metrics["edge_cases"].add("Empty content")
            elif len(fuzz_content) > 100:
                self.metrics["edge_cases"].add("Overly long content")
            elif fuzz_content.startswith("\0"):
                self.metrics["edge_cases"].add("Null byte start")
            self.metrics["code_paths"].add("insert_message")

            # Insert message
            self.insert_message("pingu", "pingi", fuzz_content)
            iteration_count += 1

        except Exception as e:
            self.metrics["crashes"] += 1
            logger.error(f"Crash detected during fuzzing operation: {e}")

    def insert_account(self, account_id, is_admin=False):
        """
        Insert an account into the Account collection.
        """
        account = {
            "accountID": account_id,
            "isAdmin": is_admin,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["accounts"].insert_one(account)

    def insert_user(self, account_id, name, birthday, nationality, gender, ethnicity):
        """
        Insert a user into the User collection.
        """
        user = {
            "accountID": account_id,
            "name": name,
            "birthday": birthday,
            "nationality": nationality,
            "gender": gender,
            "ethnicity": ethnicity,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["users"].insert_one(user)

    def insert_admin(self, account_id, name, birthday, nationality, gender, ethnicity, role):
        """
        Insert an admin into the Admin collection.
        """
        admin = {
            "accountID": account_id,
            "name": name,
            "birthday": birthday,
            "nationality": nationality,
            "gender": gender,
            "ethnicity": ethnicity,
            "role": role,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["admins"].insert_one(admin)

    def insert_message(self, sender_id, receiver_id, content):
        """
        Insert a message into the Messages collection.
        """
        message = {
            "senderID": sender_id,
            "receiverID": receiver_id,
            "content": content,
            "sent_time": datetime.utcnow(),
            "read_time": None,
            "status": "Sent",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        self.collections["messages"].insert_one(message)
        logger.info(f"Successfully inserted message: {message}")

    def generate_metrics(self):
        """
        Generate metrics and save them to a JSON file.
        """
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
            "Total Messages Inserted": self.collections["messages"].count_documents({}),
            "Unique Content Variations": len(
                set(
                    doc["content"]
                    for doc in self.collections["messages"].find({}, {"content": 1})
                )
            ),
            "Total Operations": self.metrics["total_operations"],
            "Max Iterations": MAX_ITERATIONS,
        }

        # Save metrics to JSON file
        with open("metrics_atheris.json", "w") as f:
            json.dump(metrics, f, indent=4)
        logger.info(f"Metrics saved to metrics_atheris.json: {metrics}")


def fuzz_target(data):
    fuzzer.fuzz_operation(data)


if __name__ == "__main__":
    # MongoDB URI and Database Name
    MONGO_URI = "mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0"
    DB_NAME = "test_db"

    # Initialize MongoFuzzer and seed data
    fuzzer = MongoFuzzer(MONGO_URI, DB_NAME)
    fuzzer.initialize_data()

    # Run Atheris fuzzing
    atheris.Setup(sys.argv, fuzz_target)
    atheris.Fuzz()
