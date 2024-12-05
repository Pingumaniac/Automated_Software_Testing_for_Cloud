# plot_metrics_atheris.py

import json
import matplotlib.pyplot as plt
import os


class AtherisMetricsPlotter:
    """A class for loading, processing, and plotting Atheris metrics."""

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

    def _bar_chart(self, labels, values, title, ylabel, filename, yticks=None):
        """Create a bar chart and save it as a PNG file."""
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color=["blue", "green"])
        plt.ylabel(ylabel)
        plt.title(title)
        if yticks:
            plt.yticks(yticks)
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, filename))
        plt.close()

    def plot_crash_rate(self):
        """Plot crash rate metrics in a separate file."""
        crash_rate = self.metrics.get("Crash Rate (%)", 0)
        plt.figure(figsize=(10, 6))
        plt.bar(["Crash Rate"], [crash_rate], color="red")
        plt.ylabel("Crash Rate (%)")
        plt.title("Crash Rate During Fuzz Testing")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "crash_rate.png"))
        plt.close()

    def plot_edge_case_and_execution(self):
        """Plot edge case coverage and execution paths tested in the same chart."""
        labels = ["Edge Case Coverage", "Execution Paths Tested"]
        values = [
            self.metrics.get("Edge Case Coverage", 0),
            self.metrics.get("Execution Paths Tested", 0),
        ]
        max_value = max(values)
        yticks = range(0, max_value + 2)  # Incremental y-axis ticks (0, 1, 2, etc.)
        self._bar_chart(
            labels=labels,
            values=values,
            title="Edge Case Coverage and Execution Paths Tested",
            ylabel="Values",
            filename="edge_case_and_execution.png",
            yticks=yticks,
        )
        print(f"Plots saved in '{self.output_dir}/' directory.")


def main():
    """Main function to execute the plotting."""
    metrics_plotter = AtherisMetricsPlotter(metrics_file="metrics_atheris.json")
    metrics_plotter.plot_crash_rate()
    metrics_plotter.plot_edge_case_and_execution()


if __name__ == "__main__":
    main()
