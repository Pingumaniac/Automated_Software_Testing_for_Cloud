# test_aflplusplus.py

import afl
import json
import sys
import os
import logging
from pymongo import MongoClient
from datetime import datetime, timezone
import psutil
import time
import uuid

# Configure logging to output JSON
logger = logging.getLogger("FuzzMetrics")
logger.setLevel(logging.INFO)

# Ensure the metrics_aflplusplus.json file exists
metrics_file = "metrics_aflplusplus.json"
if not os.path.exists(metrics_file):
    with open(metrics_file, 'w') as f:
        json.dump([], f)

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

json_handler = JSONFileHandler(metrics_file)
json_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(json_handler)

# Initialize MongoDB Client
mongo_uri = 'mongodb://mongo-primary:27017/?replicaSet=rs0'
client = MongoClient(mongo_uri)
db = client['social_network']

# Get process for resource utilization
process = psutil.Process(os.getpid())

def log_metric(metric_name, value, details=None):
    """Logs the metric in JSON format."""
    log_entry = {
        "metric": metric_name,
        "value": value,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    logger.info(json.dumps(log_entry))

@afl.instrument
def fuzz_insert_account(data):
    """Fuzz target for inserting into Account collection."""
    try:
        account = json.loads(data)
        account.setdefault("accountID", str(uuid.uuid4()))
        account.setdefault("isAdmin", False)
        account.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        account.setdefault("updated_at", datetime.now(timezone.utc).isoformat())

        start_time = time.time()
        result = db['Account'].insert_one(account)
        end_time = time.time()

        latency_ms = (end_time - start_time) * 1000
        log_metric("Insert Latency (ms)", latency_ms, {"collection": "Account", "operation": "insert"})

    except Exception as e:
        log_metric("Crash Detected", True, {"operation": "insert_account", "error": str(e)})
        sys.exit(1)  # AFL++ treats non-zero exit as a crash

@afl.instrument
def fuzz_query_user(data):
    """Fuzz target for querying User collection."""
    try:
        query = json.loads(data)
        start_time = time.time()
        result = db['User'].find_one(query)
        end_time = time.time()

        latency_ms = (end_time - start_time) * 1000
        log_metric("Query Latency (ms)", latency_ms, {"collection": "User", "operation": "find_one"})

    except Exception as e:
        log_metric("Crash Detected", True, {"operation": "query_user", "error": str(e)})
        sys.exit(1)

@afl.instrument
def fuzz_update_admin(data):
    """Fuzz target for updating Admin collection."""
    try:
        update_data = json.loads(data)
        if "accountID" not in update_data:
            # Cannot perform update without accountID
            return

        filter_query = {"accountID": update_data["accountID"]}
        update_fields = {k: v for k, v in update_data.items() if k != "accountID"}
        update_fields["updated_at"] = datetime.now(timezone.utc).isoformat()

        start_time = time.time()
        result = db['Admin'].update_one(filter_query, {"$set": update_fields})
        end_time = time.time()

        latency_ms = (end_time - start_time) * 1000
        log_metric("Update Latency (ms)", latency_ms, {"collection": "Admin", "operation": "update"})

    except Exception as e:
        log_metric("Crash Detected", True, {"operation": "update_admin", "error": str(e)})
        sys.exit(1)

@afl.instrument
def fuzz_delete_message(data):
    """Fuzz target for deleting from Messages collection."""
    try:
        delete_query = json.loads(data)
        start_time = time.time()
        result = db['Messages'].delete_one(delete_query)
        end_time = time.time()

        latency_ms = (end_time - start_time) * 1000
        log_metric("Delete Latency (ms)", latency_ms, {"collection": "Messages", "operation": "delete"})

    except Exception as e:
        log_metric("Crash Detected", True, {"operation": "delete_message", "error": str(e)})
        sys.exit(1)

def main():
    """Main function to start fuzzing."""
    # Initialize AFL++
    afl.init()

    while afl.loop():
        # AFL++ provides input data via stdin
        data = sys.stdin.buffer.read(1024)  # Read up to 1KB of input
        if not data:
            break  # No more input

        # Dispatch to different fuzz targets based on some heuristic
        # For simplicity, randomly choose a fuzz target
        import random
        target = random.choice([
            fuzz_insert_account,
            fuzz_query_user,
            fuzz_update_admin,
            fuzz_delete_message
        ])
        target(data)

    # After fuzzing, log resource utilization
    cpu_percent = process.cpu_percent(interval=1)
    memory_info = process.memory_info()
    memory_usage_mb = memory_info.rss / (1024 * 1024)
    disk_io = psutil.disk_io_counters()
    read_mb = disk_io.read_bytes / (1024 * 1024)
    write_mb = disk_io.write_bytes / (1024 * 1024)

    log_metric("CPU Utilization (%)", cpu_percent, {"pid": process.pid})
    log_metric("Memory Utilization (MB)", memory_usage_mb, {"pid": process.pid})
    log_metric("Disk I/O (MB)", {"read_MB": read_mb, "write_MB": write_mb}, {"pid": process.pid})

if __name__ == "__main__":
    main()
