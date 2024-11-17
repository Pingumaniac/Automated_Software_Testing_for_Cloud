# Use MongoDB as the base image
FROM mongo:6.0

# Set the working directory
WORKDIR /etc/mongo

# Copy the custom MongoDB configuration file
COPY etc/mongo/mongod.conf ./mongod.conf

# Expose the MongoDB default port
EXPOSE 27017

# Run MongoDB with replication enabled
CMD ["mongod", "--config", "/etc/mongo/mongod.conf", "--replSet", "rs0", "--bind_ip_all"]
