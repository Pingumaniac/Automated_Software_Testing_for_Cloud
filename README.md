# Unit and Fuzz Testing in Evaluating MongoDB Reliability

This project explores the use of unit testing and fuzz testing to enhance the deployment and validation of MongoDB clusters in cloud environments using Docker and Kubernetes. MongoDB's growing popularity for its flexibility and scalability underscores the importance of reliable deployment and operational testing in production settings. To address these challenges, we present an automated framework for MongoDB cluster setup, leveraging Docker and Kubernetes StatefulSets to streamline configuration, provide persistent storage, and manage replicas. The framework integrates unit testing to validate core MongoDB functionalities and employs fuzz testing with Atheris to assess resilience, edge-case handling, and execution path coverage under unpredictable inputs. While experimental results demonstrate automation and the detection of potential vulnerabilities, the scope is limited, necessitating further exploration of complementary testing approaches.

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
* Integrating fuzz testing, a type of automated software testing, to identify potential vulnerabilities.

## Features
* Automated MongoDB Setup: Easily deploy a MongoDB cluster locally or on Chameleon Cloud using Docker or Kubernetes.
* Unit Testing: Validate core MongoDB operations such as CRUD operations and replica set configurations.
* Fuzz Testing: Stress-test the MongoDB client or server with random or invalid inputs to identify crashes and vulnerabilities.
* Kubernetes StatefulSet: Deploy and manage MongoDB clusters on Kubernetes with persistent storage and replica sets.

## Tools and Technologies

1. Docker: For containerization of MongoDB.
2. Kubernetes (minikube or kubeadm): For orchestrating MongoDB clusters.
3. Python 3.12.6: For running benchmark and test scripts.
4. MongoDB CLI Tools: To interact with MongoDB from the command line.
5. Atheris: For Coverage-guided fuzz testing in Python.

## VM Distribution and Roles

This project utilizes Docker and Kubernetes across a three-VM
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

### IP addresses of each VM

1. **VM1**: `192.168.5.56` (Control and Orchestration Node)
2. **VM3**: `192.168.5.68` (Primary MongoDB Replica Set)
3. **VM4**: `192.168.5.25` (Secondary MongoDB Replica Set + MongoDB Client)

## How to build this software

### 1. Clone this repository
```
git clone git@github.com:Pingumaniac/Unit_and_Fuzz_Testing_in_Evaluating_MongoDB_Reliability.git
cd Unit_and_Fuzz_Testing_in_Evaluating_MongoDB_Reliability
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

#### a. Set up K8 with `vm1` as master, and `vm3` and `vm4` as workers.

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

## Bug tracking

* All users can view and report a bug in "GitHub Issues" of our repository.
