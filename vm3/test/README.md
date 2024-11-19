# List of possible metrics for measuring MongoDB functionality

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
