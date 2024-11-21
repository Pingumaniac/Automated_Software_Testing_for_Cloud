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

# Install pymongo pytest matplotlib yaspin python-afl coverage atheris
RUN pip3 install pymongo pytest matplotlib yaspin python-afl coverage atheris

# Copy the Python script (modify this path as needed)
# COPY test.py /app/

# Copy all application files into the container
COPY . /app/

# Command to run the Python script when the container starts
CMD ["python", "/app/test.py"]
