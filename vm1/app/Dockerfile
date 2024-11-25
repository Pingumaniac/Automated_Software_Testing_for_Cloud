# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy all project files to the container
COPY . /app/

# Install pymongo pytest matplotlib yaspin python-afl coverage atheris
RUN pip3 install pymongo pytest matplotlib yaspin python-afl coverage atheris

# Make sure all Python scripts have execution permission
RUN chmod +x /app/*.py

# Create an entrypoint script to run all tests sequentially
RUN echo '#!/bin/bash' > /app/run_tests.sh && \
    echo 'python test.py' >> /app/run_tests.sh && \
    echo 'python database_setup.py' >> /app/run_tests.sh && \
    echo 'python test_unit.py' >> /app/run_tests.sh && \
    echo 'python plot_metrics_unit.py' >> /app/run_tests.sh && \
    echo 'python test_aflplusplus.py' >> /app/run_tests.sh && \
    echo 'python plot_metrics_aflplusplus.py' >> /app/run_tests.sh && \
    echo 'python test_atheris.py' >> /app/run_tests.sh && \
    echo 'python plot_metrics_atheris.py' >> /app/run_tests.sh && \
    chmod +x /app/run_tests.sh

# Command to run the entrypoint script
CMD ["bash", "/app/run_tests.sh"]

# Copy the Python script (modify this path as needed)
# COPY test.py /app/

# Copy all application files into the container
# COPY . /app/

# Command to run the Python script when the container starts
# CMD ["python3", "/app/test.py"]
