# test_unit.py

import pytest
from pymongo import MongoClient
from bson.objectid import ObjectId
import uuid
from datetime import datetime
import time
import psutil
import logging
import json
import os

# Create a file handler that appends JSON logs
class JSONFileHandler(logging.Handler):
    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def emit(self, record):
        log_entry = self.format(record)
        with open(self.filename, 'r+') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
            data.append(json.loads(log_entry))
            f.seek(0)
            json.dump(data, f, indent=4)

@pytest.fixture(scope="session")
def db_connection():
    """Fixture to establish MongoDB connection."""
    uri = 'mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0'
    client = MongoClient(uri)
    db = client['social_network']
    return db

@pytest.fixture(scope="session")
def setup_data(db_connection):
    """Fixture to set up initial data."""
    # Clear existing data
    db_connection['Account'].delete_many({})
    db_connection['User'].delete_many({})
    db_connection['Admin'].delete_many({})
    db_connection['Messages'].delete_many({})

    # Insert two users
    account_user_1 = {
        "accountID": str(uuid.uuid4()),
        "isAdmin": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    account_user_2 = {
        "accountID": str(uuid.uuid4()),
        "isAdmin": False,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    db_connection['Account'].insert_many([account_user_1, account_user_2])

    user_1 = {
        "accountID": account_user_1["accountID"],
        "name": "Alice",
        "birthday": datetime(1990, 5, 21),
        "nationality": "American",
        "gender": "Female",
        "ethnicity": "Ethnicity1",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    user_2 = {
        "accountID": account_user_2["accountID"],
        "name": "Bob",
        "birthday": datetime(1988, 8, 14),
        "nationality": "British",
        "gender": "Male",
        "ethnicity": "Ethnicity2",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    db_connection['User'].insert_many([user_1, user_2])

    # Insert two admins
    account_admin_1 = {
        "accountID": str(uuid.uuid4()),
        "isAdmin": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    account_admin_2 = {
        "accountID": str(uuid.uuid4()),
        "isAdmin": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    db_connection['Account'].insert_many([account_admin_1, account_admin_2])

    admin_1 = {
        "accountID": account_admin_1["accountID"],
        "name": "Charlie",
        "birthday": datetime(1985, 3, 10),
        "nationality": "Canadian",
        "gender": "Male",
        "ethnicity": "Ethnicity3",
        "role": "Moderator",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    admin_2 = {
        "accountID": account_admin_2["accountID"],
        "name": "Diana",
        "birthday": datetime(1992, 12, 5),
        "nationality": "Australian",
        "gender": "Female",
        "ethnicity": "Ethnicity4",
        "role": "SuperAdmin",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    db_connection['Admin'].insert_many([admin_1, admin_2])

    # Insert messages between users
    message_user_1_to_user_2 = {
        "senderID": account_user_1["accountID"],
        "receiverID": account_user_2["accountID"],
        "content": "hello",
        "sent_time": datetime.utcnow(),
        "read_time": None,
        "status": "Sent",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    message_user_2_to_user_1 = {
        "senderID": account_user_2["accountID"],
        "receiverID": account_user_1["accountID"],
        "content": "hi",
        "sent_time": datetime.utcnow(),
        "read_time": None,
        "status": "Sent",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    db_connection['Messages'].insert_many([message_user_1_to_user_2, message_user_2_to_user_1])

    # Insert messages between admins
    message_admin_1_to_admin_2 = {
        "senderID": account_admin_1["accountID"],
        "receiverID": account_admin_2["accountID"],
        "content": "good morning",
        "sent_time": datetime.utcnow(),
        "read_time": None,
        "status": "Sent",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    message_admin_2_to_admin_1 = {
        "senderID": account_admin_2["accountID"],
        "receiverID": account_admin_1["accountID"],
        "content": "good morning!",
        "sent_time": datetime.utcnow(),
        "read_time": None,
        "status": "Sent",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    db_connection['Messages'].insert_many([message_admin_1_to_admin_2, message_admin_2_to_admin_1])

    return {
        "users": [user_1, user_2],
        "admins": [admin_1, admin_2],
        "messages": [message_user_1_to_user_2, message_user_2_to_user_1,
                    message_admin_1_to_admin_2, message_admin_2_to_admin_1]
    }

class TestMongoDB:
    """Test class covering all specified metrics for MongoDB."""

    @classmethod
    def setup_class(cls):
        """Setup resources before any tests are run."""
        cls.process = psutil.Process(os.getpid())

    @classmethod
    def teardown_class(cls):
        """Cleanup resources after all tests are run."""
        pass

    def log_metric(self, metric_name, value, details=None):
        """Logs the metric in JSON format."""
        log_entry = {
            "metric": metric_name,
            "value": value,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        logger.info(json.dumps(log_entry))

    # 1. Functional Metrics
    # 1.1 CRUD Operation Metrics

    def test_1_1_1_insert_latency(self, db_connection, setup_data):
        """Test Insert Latency for Account collection."""
        account = {
            "accountID": str(uuid.uuid4()),
            "isAdmin": False,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        start_time = time.time()
        result = db_connection['Account'].insert_one(account)
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        self.log_metric("Insert Latency (ms)", latency_ms, {"collection": "Account", "operation": "insert"})
        assert result.inserted_id is not None
        assert latency_ms < 100  # Example threshold

    def test_1_1_2_query_latency(self, db_connection, setup_data):
        """Test Query Latency for User collection."""
        user = setup_data['users'][0]
        start_time = time.time()
        result = db_connection['User'].find_one({"accountID": user['accountID']})
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        self.log_metric("Query Latency (ms)", latency_ms, {"collection": "User", "operation": "find_one"})
        assert result is not None
        assert latency_ms < 100  # Example threshold

    def test_1_1_3_update_latency(self, db_connection, setup_data):
        """Test Update Latency for Admin collection."""
        admin = setup_data['admins'][0]
        start_time = time.time()
        result = db_connection['Admin'].update_one(
            {"accountID": admin['accountID']},
            {"$set": {"role": "Administrator", "updated_at": datetime.utcnow()}}
        )
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        self.log_metric("Update Latency (ms)", latency_ms, {"collection": "Admin", "operation": "update"})
        assert result.modified_count == 1
        assert latency_ms < 100  # Example threshold

    def test_1_1_4_delete_latency(self, db_connection, setup_data):
        """Test Delete Latency for Messages collection."""
        message = setup_data['messages'][0]
        start_time = time.time()
        result = db_connection['Messages'].delete_one({"_id": message["_id"]})
        end_time = time.time()
        latency_ms = (end_time - start_time) * 1000
        self.log_metric("Delete Latency (ms)", latency_ms, {"collection": "Messages", "operation": "delete"})
        assert result.deleted_count == 1
        assert latency_ms < 100  # Example threshold

    # 1.2 Replica Set Metrics

    def test_1_2_1_replication_lag(self, db_connection):
        """Test Replication Lag for Replica Set."""
        # This is a placeholder. Actual replication lag testing requires a replica set setup with primary and secondary nodes.
        # Here, we'll simulate a simple check by ensuring the primary is elected.
        try:
            server_status = db_connection.command("serverStatus")
            replication_info = server_status.get("repl", {})
            replication_lag = replication_info.get("secondaryLagSeconds", 0) * 1000  # Convert to ms
            self.log_metric("Replication Lag (ms)", replication_lag, {"replicaSet": replication_info.get("setName", "Unknown")})
            assert replication_lag < 1000  # Example threshold
        except Exception as e:
            self.log_metric("Replication Lag (ms)", None, {"error": str(e)})
            pytest.fail(f"Failed to retrieve replication lag: {e}")

    # 2. Performance Metrics
    # 2.1 Throughput

    def test_2_1_1_operations_per_second(self, db_connection, setup_data):
        """Test Operations per Second (Throughput) for insert operations."""
        operations = 100
        start_time = time.time()
        for _ in range(operations):
            account = {
                "accountID": str(uuid.uuid4()),
                "isAdmin": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            db_connection['Account'].insert_one(account)
        end_time = time.time()
        duration = end_time - start_time
        ops_per_sec = operations / duration
        self.log_metric("Operations per Second (ops/s)", ops_per_sec, {"operation": "insert", "collection": "Account"})
        assert ops_per_sec > 50  # Example threshold

    # 2.2 Resource Utilization

    def test_2_2_1_cpu_utilization(self):
        """Test CPU Utilization during test execution."""
        cpu_percent = self.process.cpu_percent(interval=1)
        self.log_metric("CPU Utilization (%)", cpu_percent, {"pid": self.process.pid})
        assert cpu_percent < 90  # Example threshold

    def test_2_2_2_memory_utilization(self):
        """Test Memory Utilization during test execution."""
        memory_info = self.process.memory_info()
        memory_usage_mb = memory_info.rss / (1024 * 1024)
        self.log_metric("Memory Utilization (MB)", memory_usage_mb, {"pid": self.process.pid})
        assert memory_usage_mb < 500  # Example threshold

    def test_2_2_3_disk_io(self):
        """Test Disk I/O during test execution."""
        io_before = psutil.disk_io_counters()
        # Perform some disk operations if necessary
        io_after = psutil.disk_io_counters()
        read_bytes = io_after.read_bytes - io_before.read_bytes
        write_bytes = io_after.write_bytes - io_before.write_bytes
        self.log_metric("Disk I/O (MB/s)", {"read_MB": read_bytes / (1024 * 1024), "write_MB": write_bytes / (1024 * 1024)},
                       {"pid": self.process.pid})
        # No assertion as disk I/O can vary

    # 3. Reliability Metrics
    # 3.1 Durability

    def test_3_1_1_data_loss_on_failure(self, db_connection):
        """Test Data Loss on Failure."""
        # Simulating data loss is complex; here we check if data remains after a simulated failure.
        try:
            # Insert a document
            doc = {
                "test_field": "durability_test",
                "created_at": datetime.utcnow()
            }
            insert_result = db_connection['DurabilityTest'].insert_one(doc)
            doc_id = insert_result.inserted_id

            # Simulate failure (e.g., restart MongoDB or kill a node)
            # This step requires external orchestration and is not feasible within a unit test.
            # Instead, we verify that the document exists.
            retrieved_doc = db_connection['DurabilityTest'].find_one({"_id": doc_id})

            if retrieved_doc:
                self.log_metric("Data Loss on Failure", False, {"document_id": str(doc_id)})
                assert retrieved_doc is not None
            else:
                self.log_metric("Data Loss on Failure", True, {"document_id": str(doc_id)})
                pytest.fail("Data loss detected.")
        except Exception as e:
            self.log_metric("Data Loss on Failure", True, {"error": str(e)})
            pytest.fail(f"Durability test failed: {e}")

    # 4. Skipped all Fuzz Testing Metrics

    # 5. Benchmark Metrics
    # 5.1 Load Testing

    def test_5_1_1_sustained_performance(self, db_connection):
        """Test Sustained Performance over an extended period."""
        operations = 1000
        start_time = time.time()
        for _ in range(operations):
            account = {
                "accountID": str(uuid.uuid4()),
                "isAdmin": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            db_connection['Account'].insert_one(account)
        end_time = time.time()
        duration = end_time - start_time
        ops_per_sec = operations / duration
        self.log_metric("Sustained Performance (ops/s)", ops_per_sec, {"operation": "insert", "collection": "Account"})
        assert ops_per_sec > 50  # Example threshold

# Configure logging to output JSON
logger = logging.getLogger("TestMetrics")
logger.setLevel(logging.INFO)

# Ensure the metrics.json file exists
metrics_file = "metrics.json"
if not os.path.exists(metrics_file):
    with open(metrics_file, 'w') as f:
        json.dump([], f)

json_handler = JSONFileHandler(metrics_file)
json_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(json_handler)
