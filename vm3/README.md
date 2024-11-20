# About vm3

This directory contains all the code stored on `vm3` for our project. It includes unit tests to ensure MongoDB’s core functionality (CRUD operations, replica set behavior, etc.) works as expected, and it incorporates a fuzz testing component using AFL to stress test MongoDB and related applications. The files are organized into two main folders, `src` and `test`, each serving specific purposes within the project.

### `/src` Folder

1. **`app.py`**: The main FastAPI application that exposes REST API endpoints for MongoDB interactions. It enables CRUD operations and cluster management tasks, allowing users to insert, find, and manage MongoDB data and services via HTTP requests.
2. **`mongo_client.py`**: A MongoDB client manager that handles connection logic and CRUD operations. This file provides a streamlined API for other components to interact with the MongoDB replica set.
3. **`cluster_manager.py`**: Manages MongoDB cluster operations, including initializing replica sets, adding and removing nodes, and setting up MongoDB clusters in Docker or Kubernetes environments. It automates cluster management to simplify deployment and scalability.
4. **`data_manager.py`**: Manages MongoDB data operations, including creating collections, inserting documents, and performing batch CRUD operations. It also integrates with `OperationCommander` to support bulk data handling and database management.
5. **`random_json_generator.py`**: A utility for generating random JSON documents with diverse data types, ideal for testing MongoDB with varying input. It’s particularly useful for stress and fuzz testing scenarios, where data variability is essential.
6. **`operations.py`**: Defines classes for MongoDB operations, including `InsertOperation`, `UpdateOperation`, `DeleteOperation`, and more. These classes encapsulate specific MongoDB commands, providing structured operations for data management and testing.
7. **`service_layout.py`**: Describes the layout of MongoDB services in a cluster, defining which services should run on which nodes. It’s useful for managing complex MongoDB cluster configurations, particularly in distributed environments.

### `/test` Folder

