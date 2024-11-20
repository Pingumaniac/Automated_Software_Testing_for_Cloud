# src/utils.py

import statistics
import logging

class Utils:
    def __init__(self):
        self.logger = self.setup_logger()
        # Initialize metrics or other utilities as needed
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "latencies": []
        }

    def setup_logger(self):
        logger = logging.getLogger("Utils")
        logger.setLevel(logging.INFO)
        # Create handlers if not already present
        if not logger.handlers:
            c_handler = logging.StreamHandler()
            f_handler = logging.FileHandler("utils.log")
            c_handler.setLevel(logging.INFO)
            f_handler.setLevel(logging.INFO)
            # Create formatters and add to handlers
            c_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            f_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            c_handler.setFormatter(c_format)
            f_handler.setFormatter(f_format)
            # Add handlers to the logger
            logger.addHandler(c_handler)
            logger.addHandler(f_handler)
        return logger

    def calculate_average_latency(self) -> float:
        if not self.metrics["latencies"]:
            return 0.0
        average = statistics.mean(self.metrics["latencies"])
        self.logger.info(f"Calculated average latency: {average:.2f} ms")
        return average

    def get_metrics(self):
        average_latency = self.calculate_average_latency()
        metrics_summary = {
            "total_requests": self.metrics["total_requests"],
            "successful_requests": self.metrics["successful_requests"],
            "failed_requests": self.metrics["failed_requests"],
            "average_latency_ms": average_latency
        }
        self.logger.info(f"Metrics Summary: {metrics_summary}")
        return metrics_summary

    def update_metrics(self, success: bool, latency: float):
        self.metrics["total_requests"] += 1
        if success:
            self.metrics["successful_requests"] += 1
        else:
            self.metrics["failed_requests"] += 1
        self.metrics["latencies"].append(latency)
        self.logger.info(f"Updated metrics: Success={success}, Latency={latency:.2f} ms")
