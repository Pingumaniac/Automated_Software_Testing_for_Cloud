# Automated_Software_Testing_for_Cloud
CS 5287 Principles of Cloud Computing Final Project

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

## Goals

This project automates the deployment, configuration, and evaluation of MongoDB clusters using Docker and Kubernetes, with built-in support for unit testing and fuzz testing. The goal is to provide a framework for testing MongoDB performance, scalability, and reliability in various environments, including Chameleon Cloud. The project also integrates continuous integration (CI) to run tests automatically.

## Project Overview

This project aims to simplify the deployment and evaluation of MongoDB by:
* Automating the setup of MongoDB clusters using Docker and Kubernetes.
* Providing a suite of unit tests to validate basic functionality of MongoDB interactions.
* Integrating fuzz testing using tools like ClusterFuzz and OSS-Fuzz to identify potential vulnerabilities.
* Supporting CI/CD pipelines to ensure continuous testing and reliability.

## Features
* Automated MongoDB Setup: Easily deploy a MongoDB cluster locally or on Chameleon Cloud using Docker or Kubernetes.
* Unit Testing: Validate core MongoDB operations such as CRUD operations and replica set configurations.
* Fuzz Testing: Stress-test the MongoDB client or server with random or invalid inputs to identify crashes and vulnerabilities.
* CI/CD Integration: Automated testing with unit tests and fuzz testing in a continuous integration pipeline.
* Kubernetes StatefulSet: Deploy and manage MongoDB clusters on Kubernetes with persistent storage and replica sets.

## Tools and Technologies

1. Docker: For containerization of MongoDB.
2. Kubernetes (minikube or kubeadm): For orchestrating MongoDB clusters.
3. Python 3.12.6: For running benchmark and test scripts.
4. MongoDB CLI Tools: To interact with MongoDB from the command line.
5. OpenStack CLI (optional): If you plan to use Chameleon Cloud for provisioning resources.
6. ClusterFuzz/OSS-Fuzz (optional): For fuzz testing.
