# plot_metrics_aflplusplus.py

import json
import os
import matplotlib.pyplot as plt


class MetricPlotter:
    """
    Handles plotting of AFL++ fuzz testing metrics.
    """
    def __init__(self, metrics_file, plots_dir):
        self.metrics_file = metrics_file
        self.plots_dir = plots_dir
        self.metrics_data = self.load_metrics()
        self.ensure_plots_dir()

    def load_metrics(self):
        """
        Loads metrics from the JSON file.
        """
        if not os.path.exists(self.metrics_file):
            raise FileNotFoundError(f"Metrics file {self.metrics_file} does not exist.")
        with open(self.metrics_file, 'r') as f:
            return json.load(f)

    def ensure_plots_dir(self):
        """
        Ensures that the plots directory exists.
        """
        if not os.path.exists(self.plots_dir):
            os.makedirs(self.plots_dir)

    def plot_cpu_utilization(self):
        """
        Plots CPU Utilization over time.
        Metric Number: 2_2_1
        """
        cpu_data = [entry['value'] for entry in self.metrics_data if entry['metric_number'] == "2_2_1"]
        plt.figure(figsize=(10, 6))
        plt.plot(cpu_data, label='CPU Utilization (%)', color='red', marker='o')
        plt.xlabel('Fuzz Instances')
        plt.ylabel('CPU Utilization (%)')
        plt.title('2.2.1 CPU Utilization')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.plots_dir, 'cpu_utilization_aflplusplus.png'))
        plt.close()

    def plot_memory_utilization(self):
        """
        Plots Memory Utilization over time.
        Metric Number: 2_2_2
        """
        memory_data = [entry['value'] for entry in self.metrics_data if entry['metric_number'] == "2_2_2"]
        plt.figure(figsize=(10, 6))
        plt.plot(memory_data, label='Memory Utilization (MB)', color='purple', marker='o')
        plt.xlabel('Fuzz Instances')
        plt.ylabel('Memory Utilization (MB)')
        plt.title('2.2.2 Memory Utilization')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.plots_dir, 'memory_utilization_aflplusplus.png'))
        plt.close()

    def plot_crash_rate(self):
        """
        Plots Crash Rate over time.
        Metric Number: 4_1_1
        """
        crash_data = [entry['value'] for entry in self.metrics_data if entry['metric_number'] == "4_1_1"]
        plt.figure(figsize=(10, 6))
        plt.plot(crash_data, label='Crash Rate (%)', color='black', marker='o')
        plt.xlabel('Fuzz Instances')
        plt.ylabel('Crash Rate (%)')
        plt.title('4.1.1 Crash Rate')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.plots_dir, 'crash_rate_aflplusplus.png'))
        plt.close()

    def plot_edge_case_coverage(self):
        """
        Plots Edge Case Coverage over time.
        Metric Number: 4_2_1
        """
        edge_case_data = [entry['value'] for entry in self.metrics_data if entry['metric_number'] == "4_2_1"]
        plt.figure(figsize=(10, 6))
        plt.plot(edge_case_data, label='Edge Case Coverage', color='orange', marker='o')
        plt.xlabel('Fuzz Instances')
        plt.ylabel('Number of Edge Cases')
        plt.title('4.2.1 Edge Case Coverage')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.plots_dir, 'edge_case_coverage_aflplusplus.png'))
        plt.close()

    def plot_execution_paths(self):
        """
        Plots Execution Paths Tested over time.
        Metric Number: 4_2_2
        """
        execution_paths_data = [entry['value'] for entry in self.metrics_data if entry['metric_number'] == "4_2_2"]
        plt.figure(figsize=(10, 6))
        plt.plot(execution_paths_data, label='Execution Paths Tested', color='blue', marker='o')
        plt.xlabel('Fuzz Instances')
        plt.ylabel('Number of Execution Paths')
        plt.title('4.2.2 Execution Paths Tested')
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.plots_dir, 'execution_paths_aflplusplus.png'))
        plt.close()

    def generate_all_plots(self):
        """
        Generates all required plots.
        """
        self.plot_cpu_utilization()
        self.plot_memory_utilization()
        self.plot_crash_rate()
        self.plot_edge_case_coverage()
        self.plot_execution_paths()
        print(f"All plots have been generated and saved in the '{self.plots_dir}' directory.")


if __name__ == "__main__":
    METRICS_FILE = "metrics_aflplusplus.json"
    PLOTS_DIR = "plots"

    plotter = MetricPlotter(METRICS_FILE, PLOTS_DIR)
    plotter.generate_all_plots()
