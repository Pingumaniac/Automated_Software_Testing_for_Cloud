# plot_metrics_aflplusplus.py

import json
import matplotlib.pyplot as plt
import os

# Ensure the 'plots' directory exists
if not os.path.exists('plots'):
    os.makedirs('plots')

# Load metrics
metrics_file = "metrics_aflplusplus.json"
with open(metrics_file, 'r') as f:
    metrics = json.load(f)

# Initialize data containers
insert_latencies = []
query_latencies = []
update_latencies = []
delete_latencies = []
crash_counts = 0
throughputs = []
cpu_utilizations = []
memory_utilizations = []
disk_io_read = []
disk_io_write = []

# Process metrics
for m in metrics:
    metric = m.get('metric')
    value = m.get('value')
    if metric == "Insert Latency (ms)":
        insert_latencies.append(value)
    elif metric == "Query Latency (ms)":
        query_latencies.append(value)
    elif metric == "Update Latency (ms)":
        update_latencies.append(value)
    elif metric == "Delete Latency (ms)":
        delete_latencies.append(value)
    elif metric == "Crash Detected":
        crash_counts += 1
    elif metric == "Operations per Second (ops/s)":
        throughputs.append(value)
    elif metric == "CPU Utilization (%)":
        cpu_utilizations.append(value)
    elif metric == "Memory Utilization (MB)":
        memory_utilizations.append(value)
    elif metric == "Disk I/O (MB)":
        disk_io_read.append(value.get('read_MB', 0))
        disk_io_write.append(value.get('write_MB', 0))

# Plot Insert Latency
plt.figure(figsize=(10, 6))
plt.plot(insert_latencies, label='Insert Latency (ms)', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Latency (ms)')
plt.title('Insert Operation Latencies')
plt.legend()
plt.grid(True)
plt.savefig('plots/insert_latency_aflplusplus.png')
plt.close()

# Plot Query Latency
plt.figure(figsize=(10, 6))
plt.plot(query_latencies, label='Query Latency (ms)', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Latency (ms)')
plt.title('Query Operation Latencies')
plt.legend()
plt.grid(True)
plt.savefig('plots/query_latency_aflplusplus.png')
plt.close()

# Plot Update Latency
plt.figure(figsize=(10, 6))
plt.plot(update_latencies, label='Update Latency (ms)', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Latency (ms)')
plt.title('Update Operation Latencies')
plt.legend()
plt.grid(True)
plt.savefig('plots/update_latency_aflplusplus.png')
plt.close()

# Plot Delete Latency
plt.figure(figsize=(10, 6))
plt.plot(delete_latencies, label='Delete Latency (ms)', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Latency (ms)')
plt.title('Delete Operation Latencies')
plt.legend()
plt.grid(True)
plt.savefig('plots/delete_latency_aflplusplus.png')
plt.close()

# Plot Throughput
plt.figure(figsize=(10, 6))
plt.plot(throughputs, label='Operations per Second (ops/s)', color='green', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Throughput (ops/s)')
plt.title('Throughput')
plt.legend()
plt.grid(True)
plt.savefig('plots/throughput_aflplusplus.png')
plt.close()

# Plot CPU Utilization
plt.figure(figsize=(10, 6))
plt.plot(cpu_utilizations, label='CPU Utilization (%)', color='red', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('CPU Utilization (%)')
plt.title('CPU Utilization')
plt.legend()
plt.grid(True)
plt.savefig('plots/cpu_utilization_aflplusplus.png')
plt.close()

# Plot Memory Utilization
plt.figure(figsize=(10, 6))
plt.plot(memory_utilizations, label='Memory Utilization (MB)', color='purple', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Memory Utilization (MB)')
plt.title('Memory Utilization')
plt.legend()
plt.grid(True)
plt.savefig('plots/memory_utilization_aflplusplus.png')
plt.close()

# Plot Disk I/O
plt.figure(figsize=(10, 6))
plt.plot(disk_io_read, label='Disk Read (MB)', color='blue', marker='o')
plt.plot(disk_io_write, label='Disk Write (MB)', color='orange', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Disk I/O (MB)')
plt.title('Disk I/O')
plt.legend()
plt.grid(True)
plt.savefig('plots/disk_io_aflplusplus.png')
plt.close()

# Plot Crash Rate
total_operations = len(insert_latencies) + len(query_latencies) + len(update_latencies) + len(delete_latencies)
crash_rate = (crash_counts / total_operations) * 100 if total_operations > 0 else 0

plt.figure(figsize=(10, 6))
plt.bar(['Crash Rate'], [crash_rate], color='red')
plt.ylabel('Crash Rate (%)')
plt.title('Crash Rate During Fuzz Testing')
plt.savefig('plots/crash_rate_aflplusplus.png')
plt.close()

print("Fuzzing metrics plots generated and saved in the 'plots/' directory as PNG files.")
