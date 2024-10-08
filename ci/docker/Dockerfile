# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory inside the container
WORKDIR /ci/docker

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install the necessary Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files into the container
COPY . .

# Set environment variables for MongoDB connection (optional if you're using .env or another method)
ENV MONGO_URI="mongodb://admin:admin123@mongo:27017/testdb?authSource=admin"

# Expose the port your application runs on (adjust if necessary)
EXPOSE 5000

# Command to run your application
# Assuming there is a main file called 'app.py' to start the Python app
CMD ["python", "app.py"]
