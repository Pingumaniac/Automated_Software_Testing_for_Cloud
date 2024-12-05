# plot_metrics_atheris.py

import matplotlib.pyplot as plt
import os
import json


class AtherisMetricsPlotter:
    def __init__(self, metrics_file, output_dir="plots"):
        self.metrics_file = metrics_file
        self.output_dir = output_dir
        self.metrics = self._load_metrics()
        self._ensure_output_directory()

    def _load_metrics(self):
        try:
            with open(self.metrics_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Metrics file '{self.metrics_file}' not found.")
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding JSON in metrics file: {e}")

    def _ensure_output_directory(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def plot_crash_rate(self):
        crash_rate = self.metrics.get("Crash Rate (%)", 0)
        plt.figure(figsize=(8, 5))
        plt.bar(["Crash Rate (%)"], [crash_rate], color="red")
        plt.ylabel("Percentage (%)")
        plt.title("Crash Rate")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "crash_rate.png"))
        plt.close()

    def plot_edge_case_coverage(self):
        edge_case_count = self.metrics.get("Edge Case Coverage", 0)
        max_iterations = self.metrics.get("Max Iterations", 1)
        edge_case_percentage = (edge_case_count / max_iterations) * 100

        plt.figure(figsize=(8, 5))
        plt.bar(["Edge Cases", "Max Iterations", "Percentage"],
                [edge_case_count, max_iterations, edge_case_percentage],
                color=["blue", "orange", "green"])
        plt.ylabel("Values")
        plt.title("Edge Case Coverage")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "edge_case_coverage.png"))
        plt.close()

    def plot_execution_paths(self):
        execution_paths = self.metrics.get("Execution Paths Tested", 0)
        plt.figure(figsize=(8, 5))
        plt.bar(["Execution Paths"], [execution_paths], color="green")
        plt.ylabel("Count")
        plt.title("Execution Paths Tested")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "execution_paths.png"))
        plt.close()

    def plot_message_statistics(self):
        total_messages = self.metrics.get("Total Messages Inserted", 0)
        unique_content = self.metrics.get("Unique Content Variations", 0)

        plt.figure(figsize=(8, 5))
        plt.bar(["Total Messages", "Unique Content"],
                [total_messages, unique_content],
                color=["blue", "orange"])
        plt.ylabel("Count")
        plt.title("Message Statistics")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "message_statistics.png"))
        plt.close()

    def plot_all(self):
        self.plot_crash_rate()
        self.plot_edge_case_coverage()
        self.plot_execution_paths()
        self.plot_message_statistics()
        print(f"All plots saved in the directory: {self.output_dir}")


if __name__ == "__main__":
    plotter = AtherisMetricsPlotter(metrics_file="metrics_atheris.json")
    plotter.plot_all()
