# Automated_Software_Testing_for_Cloud

This project automates the deployment, configuration, and evaluation of
MongoDB clusters using Docker and Kubernetes, with built-in support for
unit testing and fuzz testing. The goal is to provide a framework for
testing MongoDB performance, scalability, and reliability in various
environments, including Chameleon Cloud.

## About Members

#### Young-jae Moon
* M.Sc. in computer science and Engineering Graduate Fellowship recipient at Vanderbilt University.
* Incoming Online Master in computer science student at Georgia Tech.
* Email: youngjae.moon@Vanderbilt.Edu

#### Robert Sheng
* M.Sc. in computer science student at Vanderbilt University
* Email: robert.sheng@Vanderbilt.Edu

#### Lisa Liu
* B.Sc. in computer science student at Vanderbilt University
* Email: chuci.liu@Vanderbilt.Edu

## Course Instructor

#### Professor Aniruddha Gokhale
* Professor in the Computer Science at Vanderbilt University
* Email: a.gokhale@Vanderbilt.edu

## Project Overview

This project aims to simplify the deployment and evaluation of MongoDB by:
* Automating the setup of MongoDB clusters using Docker and Kubernetes.
* Providing a suite of unit tests to validate basic functionality of MongoDB interactions.
* Integrating fuzz testing, a type of automated software testing, through American Fuzzy Lop (AFL) to identify potential vulnerabilities.

## Features
* Automated MongoDB Setup: Easily deploy a MongoDB cluster locally or on Chameleon Cloud using Docker or Kubernetes.
* FastAPI for MongoDB Interaction: A high-performance API built with FastAPI to interact with MongoDB.
* Unit Testing: Validate core MongoDB operations such as CRUD operations and replica set configurations.
* Fuzz Testing: Stress-test the MongoDB client or server with random or invalid inputs to identify crashes and vulnerabilities.
* Kubernetes StatefulSet: Deploy and manage MongoDB clusters on Kubernetes with persistent storage and replica sets.

## Tools and Technologies

1. Docker: For containerization of MongoDB.
2. Kubernetes (minikube or kubeadm): For orchestrating MongoDB clusters.
3. Python 3.12.6: For running benchmark and test scripts.
4. MongoDB CLI Tools: To interact with MongoDB from the command line.
5. American Fuzzy Lop (AFL): For fuzz testing.

## VM Distribution and Roles

This project utilizes Docker and Kubernetes across a four-VM
setup to automate the deployment, configuration, and testing of MongoDB
clusters. Each VM is designated for specific roles to maximize efficiency,
scalability, and reliability.

### VM1: Control and Orchestration Node
  - Master node in Kubernetes. Deploys all pods.

### VM3: Primary MongoDB Replica Set
  - Runs Kubernetes pod that hosts the primary MongoDB replica set.

### VM4: Secondary MongoDB Replica Set + MongoDB Client
  - Runs Kubernetes pod that hosts the secondary MongoDB replica set.
  - Runs Kubernetes pod that runs a Python MongoDB client to interact with the MongoDB pods.

This VM distribution maximizes the project’s flexibility by leveraging
Docker for containerized MongoDB deployments, and Kubernetes for
high-availability and clustered management. This setup facilitates comprehensive testing of MongoDB
across different environments, ensuring reliability, scalability, and
performance.

## How to build this software

### 1. Clone this repository
```
git clone https://github.com/Pingumaniac/Automated_Software_Testing_for_Cloud.git
cd Automated_Software_Testing_for_Cloud
```

### 2. Set up Docker

To install Docker on Linux, run
```
sudo bash install_docker.sh
```

To retrieve the MongoDB Docker container, run
```
sudo bash install_mongodb.sh
```

### 3. Set up Kubernetes

#### a. Set up K8 with `vm1` as master and `vm2`, `vm3`, `vm4` as workers.

Next, run b-i on `vm1`.

#### b. Install Local Path Provisioner
```
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.30/deploy/local-path-storage.yaml
```

#### c. Create service to connect Mongo nodes
```
kubectl apply -f mongo-service.yaml
```

#### d. Check service creation with
```
kubectl get service
```

#### e. Create 3 Mongo containers on the 3 worker VMs with Statefulset
```
kubectl apply -f mongo-statefulset.yaml
```

#### f. Check pod creation with
```
kubectl get pods
```

#### g. Enter into MongoDB instance
```
kubectl exec -it mongo-0 -- mongo
```

#### h. Create 3 replica sets
```
rs.initiate({
    "_id" : "rs0",
    "members" : [
        {
            "_id" : 0,
            "host" : "mongo-0.mongo.default.svc.cluster.local:27017",
        },
        {
            "_id" : 1,
            "host" : "mongo-1.mongo.default.svc.cluster.local:27017",
        },
        {
            "_id" : 2,
            "host" : "mongo-2.mongo.default.svc.cluster.local:27017",
        }
    ]
})
```

#### i. Ensure replica sets are initialized by running this command in the mongo shell on all VMs
```
kubectl exec -it mongo-[0|1|2] -- mongo

rs.status()
```

## How to Test this Software

### Steps for Full Setup

#### Step 0: Pre-requisites

1. **Ensure All VMs Are Accessible**:
   - **VM1**: `192.168.5.56` (Control and Orchestration Node)
   - **VM2**: `192.168.5.211` (Primary MongoDB Node)
   - **VM3**: `192.168.5.68` (Testing and API Server)
   - **VM4**: `192.168.5.25` (MongoDB Replica Node)

2. **Installed Software**:
   - **VM1**:
     - Kubernetes (`kubectl`) installed.
     - Docker installed.
   - **VM2 & VM4**:
     - Docker installed.
     - MongoDB containers running.
   - **VM3**:
     - Python 3.12.6 installed.
     - All required Python dependencies installed from `requirements.txt`.

3. **Ensure Network Connectivity**:
   - All VMs must be able to communicate with each other via their public or private IPs.

#### Step 1: Deploy MongoDB in Docker on VM2

**Using Docker Compose**:

Deploy a Docker container with MongoDB on VM2 using the docker-compose.yml file:
```
docker-compose up -d
```

Verify MongoDB is accessible on localhost:27017 within VM2.

**Integration Testing for Docker MongoDB**:

Run initial tests against the Docker MongoDB instance to ensure all configurations and connections are set correctly. Use FastAPI or direct CLI commands from VM4 to interact with the MongoDB instance on VM2.

#### Step 2: Deploy MongoDB in Kubernetes on VM3

**Set Up StatefulSet and Persistent Storage**:

Apply the Kubernetes manifests from the k8s folder on VM3:
```
kubectl apply -f k8s/mongo-statefulset.yaml
kubectl apply -f k8s/mongo-pvc.yaml
kubectl apply -f k8s/mongo-service.yaml
```

**Initialize MongoDB Replica Set**:

Log into the first MongoDB pod and initialize the replica set:
```
kubectl exec -it mongo-0 -- mongo --eval "rs.initiate()"
```

**Testing Kubernetes MongoDB Deployment**:

Use FastAPI on VM4 to interact with MongoDB in the Kubernetes setup.
Run unit and fuzz tests specifically targeting the Kubernetes-based MongoDB cluster.

#### Step 3: Testing Framework and Verification on VM4

**Run Unit Tests**:

Test basic MongoDB functionality (e.g., CRUD operations, replica configuration) for both Docker and Kubernetes MongoDB instances:
```
python -m unittest discover -s tests/
```

**Run Fuzz Tests**:

Run fuzz tests to validate MongoDB resilience under random and malformed inputs:
```
python3 tests/test_simple_fuzz.py
python3 tests/test_afl.py
```

Conduct fuzz testing on both the Docker-based MongoDB instance on VM2 and the Kubernetes-based instance on VM3.

## Final Testing and Documentation

### Monitor and Log

You can monitor logs on Docker, Kubernetes, MongoDB, and FastAPI to ensure
stability and identify any issues during the testing process. Use kubectl
logs for Kubernetes and docker logs for Docker MongoDB instances.

### Record Results

You can document performance metrics, any anomalies, and any differences
between the Docker and Kubernetes MongoDB instances during unit and fuzz
testing.

## Bug tracking

* All users can view and report a bug in "GitHub Issues" of our repository.
