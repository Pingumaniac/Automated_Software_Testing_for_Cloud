#!/bin/bash
CONTAINER_NAME="mongodb"
MONGODB_VERSION="mongodb/mongodb-community-server:6.0-ubi8"
echo "Retrieving MongoDB docker container"
docker run --name $CONTAINER_NAME -d $MONGODB_VERSION

# wait for container to start
sleep 1
docker exec -it $CONTAINER_NAME mongosh