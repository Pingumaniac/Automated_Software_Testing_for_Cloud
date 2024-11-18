#!/bin/bash

# Environment Variables for VM3 Configuration
# After updating with actual values, source this file using `source setup-env.sh`.

# MongoDB Configuration
export MONGO_DB_HOST="192.168.5.211"         # MongoDB primary node IP (vm2)
export MONGO_DB_PORT="27017"                 # MongoDB default port
export MONGO_DB_NAME="testdb"                # MongoDB database name
export MONGO_DB_USER="admin"                 # MongoDB username (if authentication is enabled)
export MONGO_DB_PASSWORD="password"          # MongoDB password (if authentication is enabled)
export MONGO_DB_URI="mongodb://192.168.5.211:27017,192.168.5.68:27017,192.168.5.25:27017/$MONGO_DB_NAME?replicaSet=rs0"  # MongoDB replica set URI

# FastAPI Configuration
export API_HOST="0.0.0.0"                    # Host for the FastAPI app (0.0.0.0 for accessibility)
export API_PORT="8000"                       # Port for the FastAPI app

# Kubernetes and Cloud Configuration
export KUBERNETES_CLUSTER_NAME="mongo-cluster"   # Kubernetes cluster name for MongoDB
export KUBE_NAMESPACE="mongo-namespace"          # Kubernetes namespace for MongoDB
export KUBE_CONFIG_PATH="$HOME/.kube/config"     # Path to Kubernetes config file

# Chameleon Cloud/OpenStack Configuration
export OS_USERNAME="your-openstack-username"     # OpenStack username for Chameleon Cloud
export OS_PASSWORD="your-openstack-password"     # OpenStack password
export OS_PROJECT_NAME="your-project-name"       # OpenStack project name
export OS_AUTH_URL="https://your-auth-url"       # OpenStack authentication URL
export OS_REGION_NAME="your-region"              # OpenStack region (if applicable)
export OS_KEYPAIR_NAME="your-keypair"            # Keypair name for SSH access to OpenStack VMs

# Docker Configuration
export DOCKER_COMPOSE_PATH="/src/docker-compose.yml"  # Path to docker-compose file (assuming /src folder in vm3)

# Logging and Debugging
export LOG_LEVEL="INFO"                          # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
export DEBUG_MODE="false"                        # Set to "true" for debug mode

# Miscellaneous
export CLUSTER_INIT="true"                       # Set to "true" to initialize MongoDB replica set
export BENCHMARK_ITERATIONS="1000"               # Number of iterations for performance benchmarking
