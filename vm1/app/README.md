# Test Metrics and Code Descriptions

## 1. Functional Metrics

### 1.1 CRUD Operation Metrics
* Insert Latency (ms): Measure the time taken to insert a single document or batch of documents.
* Query Latency (ms): Evaluate the time taken to retrieve documents based on: primary key lookup, range queries or compound key lookups., text search queries (if indexes are enabled).
* Update Latency (ms): Measure the time to update one or more fields in existing documents.
* Delete Latency (ms): Measure the time to delete documents based on specific criteria.

### 1.2 Replica Set Metrics
* Replication Lag (ms): Time difference between when a write is applied to the primary node and when it is replicated to secondaries.

## 2. Performance Metrics

### 2.1 Throughput
* Operations per Second (ops/s): Measure the number of CRUD operations MongoDB can process per second under a specific workload.

### 2.2 Resource Utilization
* CPU Utilization (%): Measure CPU usage under various workloads.
* Memory Utilization (%): Track memory usage during read and write-intensive operations.
* Disk I/O (MB/s): Monitor disk reads/writes during heavy data insertions or queries.

## 3. Reliability Metrics

### 3.1 Fault Tolerance
* Failover Time (ms): Measure the time taken for the replica set to elect a new primary when the current primary fails.
* Data Consistency: Verify consistency between primary and secondary nodes under normal operations and after failover.

### 3.2 Durability
* Data Loss on Failure: Measure the extent of data loss (if any) under sudden node or cluster failures.

## 4. Fuzz Testing Metrics

### 4.1 Resilience
* Crash Rate (% of operations): Percentage of operations causing crashes during fuzz testing.

### 4.2 Vulnerability Metrics
* Edge Case Coverage: Number and variety of edge cases detected during fuzz testing.
* Execution Paths Tested: Percentage of code paths executed during fuzz testing.

## 5. Benchmark Metrics

### 5.1 Load Testing
* Sustained Performance: Measure system performance over an extended period (e.g., 1 hour test).


## Code Descriptions

1. **`test_unit.py`**: Contains unit tests to validate MongoDB’s core functionalities, including CRUD operations and replica set configurations. These tests ensure MongoDB operates as expected in both standalone and replica set modes.
2. **`test_simple_fuzz.py`**: A simple fuzz testing script that performs CRUD operations using randomly generated data. This script is designed to assess MongoDB’s resilience to unexpected or edge-case inputs by inserting, updating, and deleting randomized documents.
3. **`test_afl.py`**: Integrates American Fuzzy Lop (AFL) for advanced fuzz testing. This script generates malformed or random inputs to identify vulnerabilities or stability issues in MongoDB, helping ensure robustness under diverse data conditions.
4. **`test_performance.py`**: A script designed to evaluate MongoDB’s performance. It captures metrics such as response time and throughput.
5. **`mongo_client.py`**: A MongoDB client manager that handles connection logic and CRUD operations. This file provides a streamlined API for other components to interact with the MongoDB replica set.
6. **`random_json_generator.py`**: A utility for generating random JSON documents with diverse data types, ideal for testing MongoDB with varying input. It’s particularly useful for stress and fuzz testing scenarios, where data variability is essential.