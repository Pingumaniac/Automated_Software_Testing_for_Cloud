# About vm2

This directory contains all the code stored in `vm2` for our project. As the **Primary MongoDB Node**, `vm2` is responsible for initiating and managing the MongoDB replica set, hosting the primary instance in the MongoDB cluster. This node supports high availability, scalability, and fault tolerance within the cluster by managing persistent data storage and serving as the primary endpoint for MongoDB interactions.

### Key Components on `vm2`

1. **MongoDB Configuration Files (`mongod.conf`)**: Configures MongoDB to run as the primary node in the replica set. This file defines essential settings such as networking, storage, and replica set membership.
2. **Persistent Data Directory (`/data/db`)**: Provides a storage path for MongoDB data files, ensuring data durability. This directory is essential for maintaining data integrity across restarts or migrations.
3. **Replica Set Initialization Script (`init_replica.sh`)**: A script that can be run to initialize the MongoDB replica set and add an other node (`vm4`) as a replica. This script is useful for quick setup and configuration of the replica set.
