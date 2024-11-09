# Use MongoDB as the base image
FROM mongo:6.0

# Expose the MongoDB port
EXPOSE 27017

# Copy a custom MongoDB config file if needed (optional)
COPY mongo.conf /etc/mongo/mongo.conf

# Run MongoDB with replication enabled (this command assumes you configure replication)
CMD ["mongod", "--replSet", "rs0", "--bind_ip_all"]
