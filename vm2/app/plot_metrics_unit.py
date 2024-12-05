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

    def _bar_chart(self, labels, values, title, xlabel, ylabel, filename):
        """Create a bar chart and save it as a PNG file."""
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color="skyblue")
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.title(title)
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, filename))
        plt.close()

    def plot_crud_latencies(self):
        """Plot CRUD operation latencies."""
        metrics = {
            "Insert": self._filter_metrics("Insert Latency (ms)"),
            "Query": self._filter_metrics("Query Latency (ms)"),
            "Update": self._filter_metrics("Update Latency (ms)"),
            "Delete": self._filter_metrics("Delete Latency (ms)"),
        }
        labels = metrics.keys()
        averages = [sum(values) / len(values) if values else 0 for values in metrics.values()]
        self._bar_chart(
            labels=labels,
            values=averages,
            title="CRUD Operation Latencies (Average)",
            xlabel="Operation",
            ylabel="Latency (ms)",
            filename="crud_latencies.png",
        )

    def plot_system_utilizations(self):
        """Plot system utilization metrics in a bar chart."""
        metrics = {
            "CPU Utilization (%)": sum(self._filter_metrics("CPU Utilization (%)")),
            "Memory Utilization (MB)": sum(self._filter_metrics("Memory Utilization (MB)")),
            "Throughput (ops/s)": sum(self._filter_metrics("Operations per Second (ops/s)")),
        }
        labels = metrics.keys()
        values = metrics.values()
        self._bar_chart(
            labels=labels,
            values=values,
            title="System Utilizations and Throughput",
            xlabel="Metrics",
            ylabel="Values",
            filename="system_utilizations.png",
        )

    def plot_all(self):
        """Generate all plots."""
        self.plot_crud_latencies()
        self.plot_system_utilizations()
        print(f"Plots generated and saved in the '{self.output_dir}/' directory.")


def main():
    """Main function to execute the plotting."""
    metrics_plotter = MetricsPlotter(metrics_file="metrics_unit.json")
    metrics_plotter.plot_all()

if __name__ == "__main__":
    main()
