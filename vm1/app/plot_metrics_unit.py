# plot_metrics_unit.py

import json
import matplotlib.pyplot as plt
import os

class MetricsPlotter:
    """A class for loading, processing, and plotting metrics."""

    def __init__(self, metrics_file, output_dir="plots"):
        """Initialize the MetricsPlotter with a metrics file and output directory."""
        self.metrics_file = metrics_file
        self.output_dir = output_dir
        self.metrics = self._load_metrics()
        self._ensure_output_directory()

    def _load_metrics(self):
        """Load metrics from the JSON file."""
        try:
            with open(self.metrics_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Metrics file '{self.metrics_file}' not found.")
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding JSON in metrics file: {e}")

    def _ensure_output_directory(self):
        """Ensure the output directory for plots exists."""
        os.makedirs(self.output_dir, exist_ok=True)

    def _filter_metrics(self, metric_name):
        """Filter metrics by name and extract their values."""
        return [m['value'] for m in self.metrics if m['metric'] == metric_name]

    def _plot(self, x_values, y_values, labels, title, xlabel, ylabel, filename):
        """Create a plot and save it as a PNG file."""
        plt.figure(figsize=(10, 6))
        for y, label in zip(y_values, labels):
            plt.plot(x_values, y, label=label, marker='o')
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.title(title)
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(self.output_dir, filename))
        plt.close()

    def plot_crud_latencies(self):
        """Plot CRUD operation latencies."""
        metrics = {
            "Insert Latency (ms)": self._filter_metrics("Insert Latency (ms)"),
            "Query Latency (ms)": self._filter_metrics("Query Latency (ms)"),
            "Update Latency (ms)": self._filter_metrics("Update Latency (ms)"),
            "Delete Latency (ms)": self._filter_metrics("Delete Latency (ms)"),
        }
        x_values = range(len(next(iter(metrics.values()), [])))  # Assuming equal length
        self._plot(
            x_values=x_values,
            y_values=metrics.values(),
            labels=metrics.keys(),
            title="CRUD Operation Latencies",
            xlabel="Test Instances",
            ylabel="Latency (ms)",
            filename="crud_latencies.png",
        )

    def plot_throughput(self):
        """Plot throughput metrics."""
        throughputs = self._filter_metrics("Operations per Second (ops/s)")
        x_values = range(len(throughputs))
        self._plot(
            x_values=x_values,
            y_values=[throughputs],
            labels=["Operations per Second (ops/s)"],
            title="Throughput",
            xlabel="Test Instances",
            ylabel="Throughput (ops/s)",
            filename="throughput.png",
        )

    def plot_cpu_utilization(self):
        """Plot CPU utilization metrics."""
        cpu_utilizations = self._filter_metrics("CPU Utilization (%)")
        x_values = range(len(cpu_utilizations))
        self._plot(
            x_values=x_values,
            y_values=[cpu_utilizations],
            labels=["CPU Utilization (%)"],
            title="CPU Utilization",
            xlabel="Test Instances",
            ylabel="CPU Utilization (%)",
            filename="cpu_utilization.png",
        )

    def plot_memory_utilization(self):
        """Plot memory utilization metrics."""
        memory_utilizations = self._filter_metrics("Memory Utilization (MB)")
        x_values = range(len(memory_utilizations))
        self._plot(
            x_values=x_values,
            y_values=[memory_utilizations],
            labels=["Memory Utilization (MB)"],
            title="Memory Utilization",
            xlabel="Test Instances",
            ylabel="Memory Utilization (MB)",
            filename="memory_utilization.png",
        )

    def plot_all(self):
        """Generate all plots."""
        self.plot_crud_latencies()
        self.plot_throughput()
        self.plot_cpu_utilization()
        self.plot_memory_utilization()
        print(f"Plots generated and saved in the '{self.output_dir}/' directory.")


def main():
    """Main function to execute the plotting."""
    metrics_plotter = MetricsPlotter(metrics_file="metrics_unit.json")
    metrics_plotter.plot_all()

if __name__ == "__main__":
    main()
