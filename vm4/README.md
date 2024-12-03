# About vm4

This directory contains all the code stored in `vm4` for our project. As a **MongoDB Replica Node**, `vm4` supports data redundancy and high availability by replicating data from the primary node (`vm3`). It contributes to the MongoDB replica set, ensuring that data remains accessible even if the primary node is unavailable.

### Key Components on `vm4`

1. **MongoDB Configuration Files (`mongod.conf`)**: Configures MongoDB to operate as a replica in the replica set, allowing it to synchronize data with the primary node and other replicas.
2. **Persistent Data Directory (`/data/db`)**: Provides storage for MongoDB’s replicated data, ensuring that data is backed up and synchronized with the primary node (`vm3`).
3. **Replica Set Initialization**: Although usually managed from `vm3`, `vm4` can be initialized and added to the replica set to complete the MongoDB cluster configuration, enhancing the system’s resilience and scalability.
