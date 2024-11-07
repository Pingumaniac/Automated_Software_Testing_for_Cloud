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
5. OpenStack CLI: To use Chameleon Cloud for provisioning resources.
6. Ansible: To automate provisioning and configuration of Chameleon Cloud.
6. American Fuzzy Lop (AFL): For fuzz testing.

## VM Distribution and Roles

This project utilizes Docker, Kubernetes, and Ansible across a four-VM
setup to automate the deployment, configuration, and testing of MongoDB
clusters. Each VM is designated for specific roles to maximize efficiency,
scalability, and reliability.

### VM1: Control and Orchestration Node

- **Tools**:
  - **Ansible**: Automates the setup and management of Docker, Kubernetes,
  and MongoDB configurations on other VMs.
  - **OpenStack CLI**: Manages cloud resources on Chameleon Cloud.
  - **Kubernetes CLI** (`kubectl`): Controls Kubernetes deployments across
  VMs.

- **Role**:
  - Serves as the primary orchestration node, running Ansible playbooks
  to deploy and configure services on VM2, VM3, and VM4.
  - Manages testing workflows, including setup and teardown, to ensure
  each service is deployed correctly and can communicate across VMs.
  - Acts as the control point for testing environments, deploying and
  monitoring MongoDB configurations across Docker and Kubernetes.

### VM2: Primary MongoDB Node

- **Tools**:
  - **Docker**: Hosts MongoDB in a container for isolated deployment.
  - **Kubernetes**: Operates as a Kubernetes worker node, enabling MongoDB
  to be managed in a StatefulSet configuration with persistent storage.

- **Role**:
  - Acts as the primary MongoDB instance or leader in the MongoDB
  Kubernetes StatefulSet.
  - Maintains persistent storage managed by Kubernetes for data durability
  across pod restarts or migrations.
  - Supports replication and high availability as part of a clustered
  MongoDB setup, essential for scalability and reliability testing.

### VM3: Testing and API Server

- **Tools**:
  - **Python**: Runs unit and fuzz testing scripts on MongoDB deployments.
  - **FastAPI**: Provides an API interface to interact with MongoDB for
  testing CRUD operations and replica management.
  - **Docker**: Hosts FastAPI in a containerized environment, facilitating
  easy deployment and scaling of API endpoints.
  - **Kubernetes (optional)**: Manages the deployment and scaling of
  testing services if needed.

- **Role**:
  - Hosts unit and fuzz tests targeting both Docker and Kubernetes MongoDB
  instances to validate functionality, reliability, and performance.
  - Exposes an API via FastAPI, allowing CRUD operations and MongoDB
  interactions through standardized endpoints.
  - Acts as the central interface for testing MongoDB operations across
  multiple environments, supporting API-driven tests, fuzzing, and load tests.

### VM4: MongoDB Replica Node

- **Tools**:
  - **Docker**: Runs MongoDB as a containerized replica.
  - **Kubernetes**: Functions as a worker node in the Kubernetes cluster
  to provide replication and high availability in coordination with VM2.

- **Role**:
  - Acts as a replica node in the MongoDB Kubernetes StatefulSet, ensuring
  data redundancy and high availability.
  - Synchronizes data with the primary MongoDB instance on VM2, providing
  a robust environment for testing replica set configurations.
  - Contributes to the Kubernetes-managed high-availability MongoDB
  cluster, supporting failover, replication, and resiliency tests.


This VM distribution maximizes the project’s flexibility by leveraging
Docker for containerized MongoDB deployments, Kubernetes for
high-availability and clustered management, and Ansible for orchestration
and automation. This setup facilitates comprehensive testing of MongoDB
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

#### a. Set up K8 with `vm1` as master and `vm2`, `vm3`, `vm4` as workers

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

## How to test this software

### Running MongoDB Cluster

#### 1. Using Docker (For Local Testing)
To spin up a MongoDB container locally using Docker:

```
docker-compose up -d
```

This command will start a MongoDB instance running on port 27017. You can change configuration settings in the docker-compose.yml file.

#### 2. Using Kubernetes (For Scalable Testing)
Deploy MongoDB as a StatefulSet in Kubernetes:

```
kubectl apply -f k8s/mongo-statefulset.yaml
```

This will deploy a MongoDB replica set in a Kubernetes cluster, with persistent storage for each pod.

#### 3. Expose MongoDB Service
```
kubectl apply -f k8s/mongo-service.yaml
```

This creates a service to expose the MongoDB cluster so you can connect to it externally.

### Automated Testing

#### 1. Unit Testing

Unit tests are used to validate MongoDB operations (e.g., CRUD operations, connections, etc.). You can run the unit tests to validate MongoDB interactions:

```
python -m unittest discover -s tests/
```

Example unit tests include:
* Connection tests.
* Insert, find, update, and delete operations.
* Replica set configuration testing.

#### 2. Fuzz Testing

Fuzz testing randomly inputs malformed data into MongoDB operations to identify crashes and vulnerabilities. We integrate simple fuzz test and AFL to automate this process.

Install python-afl on your local machine or set it up in the cloud.
```
pip3 install python-afl
```

Then, you can execute the following commands to run the fuzz tests:
```
python3 tests/test_simple_fuzz.py
python3 tests/test_afl.py
```

## Bug tracking

* All users can view and report a bug in "GitHub Issues" of our repository.
