# test_aflplusplus.py

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from threading import Thread

import psutil

# Ensure AFL++ and necessary tools are installed
# You might need to install python-afl and other dependencies
# pip install python-afl psutil

class MetricLogger:
    """
    Handles logging of metrics to a JSON file.
    """
    def __init__(self, metrics_file):
        self.metrics_file = metrics_file
        # Initialize the metrics file if it doesn't exist
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, 'w') as f:
                json.dump([], f)
        # Set up logging
        self.logger = logging.getLogger("AFL++Metrics")
        self.logger.setLevel(logging.INFO)
        self.handler = JSONFileHandler(self.metrics_file)
        self.logger.addHandler(self.handler)

    def log_metric(self, metric_number, metric_name, value, details=None):
        """
        Logs a single metric entry.
        """
        log_entry = {
            "metric_number": metric_number,
            "metric_name": metric_name,
            "value": value,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.logger.info(json.dumps(log_entry))


class JSONFileHandler(logging.Handler):
    """
    Custom logging handler to append JSON objects to a file.
    """
    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def emit(self, record):
        log_entry = self.format(record)
        with open(self.filename, 'r+') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
            data.append(json.loads(log_entry))
            f.seek(0)
            json.dump(data, f, indent=4)


class ResourceMonitor(Thread):
    """
    Monitors CPU and Memory utilization at regular intervals.
    """
    def __init__(self, process, logger, interval=1):
        super().__init__()
        self.process = process
        self.logger = logger
        self.interval = interval
        self._stop_event = False

    def run(self):
        while not self._stop_event:
            cpu = self.process.cpu_percent(interval=None)
            memory = self.process.memory_info().rss / (1024 * 1024)  # Convert to MB
            self.logger.log_metric("2_2_1", "CPU Utilization (%)", cpu)
            self.logger.log_metric("2_2_2", "Memory Utilization (MB)", memory)
            time.sleep(self.interval)

    def stop(self):
        self._stop_event = True


class AFLFuzzer:
    """
    Manages the AFL++ fuzzing process and metrics collection.
    """
    def __init__(self, input_dir, output_dir, target_script, duration, metrics_file):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.target_script = target_script
        self.duration = duration
        self.metrics_file = metrics_file
        self.logger = MetricLogger(self.metrics_file)
        self.fuzzer_process = None
        self.resource_monitor = None

    def prepare_seed_inputs(self):
        """
        Prepares seed input files for fuzzing.
        """
        if not os.path.exists(self.input_dir):
            os.makedirs(self.input_dir)
            # Example seed inputs
            valid_input = {
                "accountID": "123e4567-e89b-12d3-a456-426614174000",
                "isAdmin": False,
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-01T12:00:00Z"
            }
            malformed_input = {
                "accountID": 12345,
                "isAdmin": "yes",
                "created_at": "invalid_date",
                "updated_at": "2023-01-01T12:00:00Z"
            }
            with open(os.path.join(self.input_dir, "valid_input.json"), 'w') as f:
                json.dump(valid_input, f)
            with open(os.path.join(self.input_dir, "malformed_input.json"), 'w') as f:
                json.dump(malformed_input, f)

    def start_fuzzing(self):
        """
        Starts the AFL++ fuzzing process.
        """
        self.prepare_seed_inputs()
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Start the fuzzing process
        self.fuzzer_process = subprocess.Popen([
            "afl-fuzz",
            "-i", self.input_dir,
            "-o", self.output_dir,
            "--", sys.executable, self.target_script
        ])

        # Start resource monitoring
        self.resource_monitor = ResourceMonitor(psutil.Process(self.fuzzer_process.pid), self.logger)
        self.resource_monitor.start()

        # Monitor for crashes
        try:
            start_time = time.time()
            while time.time() - start_time < self.duration:
                time.sleep(5)  # Check every 5 seconds
                crashes = self.get_crash_count()
                self.logger.log_metric("4_1_1", "Crash Rate (% of operations)", crashes)
        except KeyboardInterrupt:
            print("Fuzzing interrupted by user.")
        finally:
            self.stop_fuzzing()

    def get_crash_count(self):
        """
        Retrieves the number of crashes from the AFL++ output directory.
        """
        crashes_dir = os.path.join(self.output_dir, "crashes")
        if not os.path.exists(crashes_dir):
            return 0
        return len(os.listdir(crashes_dir))

    def stop_fuzzing(self):
        """
        Stops the fuzzing process and resource monitoring.
        """
        if self.fuzzer_process:
            self.fuzzer_process.terminate()
            self.fuzzer_process.wait()
        if self.resource_monitor:
            self.resource_monitor.stop()
            self.resource_monitor.join()


if __name__ == "__main__":
    # Configuration
    INPUT_DIR = "afl_inputs_account"
    OUTPUT_DIR = "afl_outputs_account"
    TARGET_SCRIPT = "fuzz_account.py"  # Replace with your fuzz target script
    DURATION = 60  # Duration in seconds
    METRICS_FILE = "metrics_aflplusplus.json"

    # Initialize and start the fuzzer
    fuzzer = AFLFuzzer(INPUT_DIR, OUTPUT_DIR, TARGET_SCRIPT, DURATION, METRICS_FILE)
    fuzzer.start_fuzzing()
