#!/bin/bash

# This is a template for environment variables. Update the values according to your environment.
# After updating, rename this file to `setup-env.sh` and source it to configure your environment.
# Example: `source setup-env.sh`

# MongoDB Configuration
export MONGO_DB_HOST="localhost"          # The MongoDB host (default is localhost for local development)
export MONGO_DB_PORT="27017"              # MongoDB port (default is 27017)
export MONGO_DB_NAME="testdb"             # The MongoDB database to use
export MONGO_DB_USER="admin"              # MongoDB username (if authentication is enabled)
export MONGO_DB_PASSWORD="password"       # MongoDB password (if authentication is enabled)
export MONGO_DB_URI="mongodb://$MONGO_DB_HOST:$MONGO_DB_PORT/$MONGO_DB_NAME"  # Full MongoDB URI (override if necessary)

# FastAPI Configuration
export API_HOST="0.0.0.0"                 # Host for the FastAPI app (default is 0.0.0.0 for accessibility)
export API_PORT="8000"                    # Port for the FastAPI app

# Kubernetes and Cloud Configuration
export KUBERNETES_CLUSTER_NAME="mongo-cluster"  # Kubernetes cluster name (for Kubernetes-based deployments)
export KUBE_NAMESPACE="mongo-namespace"         # Kubernetes namespace for the MongoDB cluster
export KUBE_CONFIG_PATH="$HOME/.kube/config"    # Path to your Kubernetes config file

# Chameleon Cloud/OpenStack Configuration
export OS_USERNAME="your-openstack-username"    # OpenStack username (for Chameleon Cloud)
export OS_PASSWORD="your-openstack-password"    # OpenStack password
export OS_PROJECT_NAME="your-project-name"      # OpenStack project name
export OS_AUTH_URL="https://your-auth-url"      # OpenStack authentication URL
export OS_REGION_NAME="your-region"             # OpenStack region (if applicable)
export OS_KEYPAIR_NAME="your-keypair"           # Keypair name for SSH access to OpenStack VMs

# Docker Configuration
export DOCKER_COMPOSE_PATH="./docker-compose.yml"  # Path to your docker-compose file (for local Docker deployments)

# Logging and Debugging
export LOG_LEVEL="INFO"                         # Log level for the application (DEBUG, INFO, WARNING, ERROR, CRITICAL)
export DEBUG_MODE="false"                       # Set to true to enable debug mode

# Miscellaneous
export CLUSTER_INIT="true"                      # Set to "true" if MongoDB replica set initialization is required
export BENCHMARK_ITERATIONS="1000"              # Number of iterations for running performance benchmarks
