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

    def plot_crash_rate(self):
        """Plot crash rate metrics."""
        crash_rate = self.metrics.get("Crash Rate (%)", 0)
        plt.figure(figsize=(10, 6))
        plt.bar(["Crash Rate"], [crash_rate], color="red")
        plt.ylabel("Crash Rate (%)")
        plt.title("Crash Rate During Fuzz Testing")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "crash_rate.png"))
        plt.close()

    def plot_edge_case_coverage(self):
        """Plot edge case coverage metrics."""
        edge_case_coverage = self.metrics.get("Edge Case Coverage", 0)
        plt.figure(figsize=(10, 6))
        plt.bar(["Edge Case Coverage"], [edge_case_coverage], color="blue")
        plt.ylabel("Number of Edge Cases")
        plt.title("Edge Case Coverage")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "edge_case_coverage.png"))
        plt.close()

    def plot_execution_paths_tested(self):
        """Plot execution paths tested metrics."""
        execution_paths_tested = self.metrics.get("Execution Paths Tested", 0)
        plt.figure(figsize=(10, 6))
        plt.bar(["Execution Paths Tested"], [execution_paths_tested], color="green")
        plt.ylabel("Number of Execution Paths")
        plt.title("Execution Paths Tested")
        plt.grid(axis="y")
        plt.savefig(os.path.join(self.output_dir, "execution_paths_tested.png"))
        plt.close()

    def plot_all(self):
        """Generate all plots."""
        self.plot_crash_rate()
        self.plot_edge_case_coverage()
        self.plot_execution_paths_tested()
        print(f"Plots generated and saved in the '{self.output_dir}/' directory.")


def main():
    """Main function to execute the plotting."""
    metrics_plotter = AtherisMetricsPlotter(metrics_file="metrics_atheris.json")
    metrics_plotter.plot_all()


if __name__ == "__main__":
    main()
