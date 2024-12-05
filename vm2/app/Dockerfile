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

# Install pymongo pytest psutil pytest-cov matplotlib yaspin coverage atheris
RUN pip3 install pymongo pytest psutil pytest-cov matplotlib yaspin coverage atheris

# Copy all application files into the container
COPY . /app/

# Command to run the Python script when the container starts
CMD ["python", "/app/test.py"]
# CMD ["bash", "-c", "python /app/test.py && tail -f /dev/null"]

# Ensure the script has execution permissions
# RUN chmod +x /app/run_tests.sh

# Command to run the Python script when the container starts
# CMD ["bash", "/app/run_tests.sh"]
