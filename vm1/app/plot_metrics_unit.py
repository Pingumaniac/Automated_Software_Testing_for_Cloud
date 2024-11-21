# plot_metrics_unit.py

import json
import matplotlib.pyplot as plt
import os

# Ensure the 'plots' directory exists
if not os.path.exists('plots'):
    os.makedirs('plots')

# Load metrics
with open('metrics.json', 'r') as f:
    metrics = json.load(f)

# Filter metrics by type
insert_latencies = [m['value'] for m in metrics if m['metric'] == "Insert Latency (ms)"]
query_latencies = [m['value'] for m in metrics if m['metric'] == "Query Latency (ms)"]
update_latencies = [m['value'] for m in metrics if m['metric'] == "Update Latency (ms)"]
delete_latencies = [m['value'] for m in metrics if m['metric'] == "Delete Latency (ms)"]
throughputs = [m['value'] for m in metrics if m['metric'] == "Operations per Second (ops/s)"]
cpu_utilizations = [m['value'] for m in metrics if m['metric'] == "CPU Utilization (%)"]
memory_utilizations = [m['value'] for m in metrics if m['metric'] == "Memory Utilization (MB)"]

# Plot Insert Latency
plt.figure(figsize=(10, 6))
plt.plot(insert_latencies, label='Insert Latency (ms)', marker='o')
plt.plot(query_latencies, label='Query Latency (ms)', marker='o')
plt.plot(update_latencies, label='Update Latency (ms)', marker='o')
plt.plot(delete_latencies, label='Delete Latency (ms)', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Latency (ms)')
plt.title('CRUD Operation Latencies')
plt.legend()
plt.grid(True)
plt.savefig('plots/crud_latencies.png')
plt.close()

# Plot Throughput
plt.figure(figsize=(10, 6))
plt.plot(throughputs, label='Operations per Second (ops/s)', color='green', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Throughput (ops/s)')
plt.title('Throughput')
plt.legend()
plt.grid(True)
plt.savefig('plots/throughput.png')
plt.close()

# Plot CPU Utilization
plt.figure(figsize=(10, 6))
plt.plot(cpu_utilizations, label='CPU Utilization (%)', color='red', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('CPU Utilization (%)')
plt.title('CPU Utilization')
plt.legend()
plt.grid(True)
plt.savefig('plots/cpu_utilization.png')
plt.close()

# Plot Memory Utilization
plt.figure(figsize=(10, 6))
plt.plot(memory_utilizations, label='Memory Utilization (MB)', color='purple', marker='o')
plt.xlabel('Test Instances')
plt.ylabel('Memory Utilization (MB)')
plt.title('Memory Utilization')
plt.legend()
plt.grid(True)
plt.savefig('plots/memory_utilization.png')
plt.close()

print("Plots generated and saved in the 'plots/' directory as PNG files.")
