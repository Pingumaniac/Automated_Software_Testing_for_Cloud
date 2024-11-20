# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install pymongo
RUN pip install pymongo

# Copy the Python script (modify this path as needed)
COPY test.py /app/

# Command to run the Python script when the container starts
CMD ["python", "/app/test.py"]
