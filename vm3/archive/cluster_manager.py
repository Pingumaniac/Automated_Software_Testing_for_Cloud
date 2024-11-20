import subprocess
import logging
import json
import os
import random
from pathlib import Path

class ClusterManager:
    def __init__(self, username, password, verbose=False):
        self.username = username
        self.password = password
        self.hosts = self.get_hosts_from_json()
        self.randomly_assign_host_roles()
        self.mongo_url = f"mongodb://{self.get_public_address(self.leader)}:27017"
        self.setup_logging(verbose)
        self.logger.info(f"MongoDB Leader URL: {self.mongo_url}")
        self.logger.info(f"Available Hosts: {len(self.hosts)}")

    def setup_logging(self, verbose):
        """Sets up logging."""
        self.logger = logging.getLogger('ClusterManager')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    def run_command(self, command):
        """Helper method to run shell commands."""
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode != 0:
            self.logger.error(f"Command failed: {error.decode()}")
        return output.decode()

    def get_hosts_from_json(self):
        """Retrieve hosts information from a JSON file."""
        hosts_file = Path(__file__).parent / 'hosts.json'
        hosts = []
        try:
            with open(hosts_file) as f:
                hosts = json.load(f)['hosts']
        except Exception as e:
            self.logger.error(f"Failed to read hosts file: {e}")
        return hosts

    def randomly_assign_host_roles(self):
        """Randomly assign leader and followers."""
        random.shuffle(self.hosts)
        self.leader = self.hosts[0]
        self.followers = self.hosts[1:]

    def get_public_address(self, host):
        """Get public address of a host."""
        return host['public']

    def get_private_address(self, host):
        """Get private address of a host."""
        return host['private']

    def setup_docker_cluster(self):
        """Set up MongoDB cluster using Docker."""
        self.logger.info("Setting up Docker-based MongoDB cluster...")
        for host in self.hosts:
            public_address = self.get_public_address(host)
            self.logger.info(f"Setting up MongoDB on host {public_address}")
            self.run_command(f"ssh {self.username}@{public_address} 'docker run -d -p 27017:27017 --name mongo mongo:latest'")

    def setup_kubernetes_cluster(self):
        """Set up MongoDB cluster using Kubernetes."""
        self.logger.info("Setting up MongoDB cluster with Kubernetes...")
        self.run_command("kubectl apply -f kubernetes/mongo-deployment.yml")

    def scale_kubernetes_cluster(self, replicas):
        """Scale the MongoDB Kubernetes cluster."""
        self.logger.info(f"Scaling MongoDB cluster to {replicas} replicas...")
        self.run_command(f"kubectl scale --replicas={replicas} deployment/mongo")

    def init_replica_set(self):
        """Initialize MongoDB replica set."""
        self.logger.info("Initializing MongoDB replica set...")
        command = (
            f"docker exec -it mongo mongo --eval 'rs.initiate({{_id: \"rs0\", members: [{{ _id: 0, host: \"{self.get_public_address(self.leader)}:27017\" }}]}})'"
        )
        self.run_command(command)

    def add_node_to_replica_set(self, node):
        """Add a node to the MongoDB replica set."""
        self.logger.info(f"Adding node {self.get_public_address(node)} to replica set...")
        command = (
            f"docker exec -it mongo mongo --eval 'rs.add(\"{self.get_public_address(node)}:27017\")'"
        )
        self.run_command(command)

    def rebalance_cluster(self):
        """Rebalance the cluster."""
        self.logger.info("Rebalancing MongoDB cluster...")

    def remove_node(self, node):
        """Remove a node from the cluster."""
        self.logger.info(f"Removing node {self.get_public_address(node)} from cluster...")
        self.run_command(f"docker exec -it mongo mongo --eval 'rs.remove(\"{self.get_public_address(node)}:27017\")'")

    def graceful_failover_node(self, node):
        """Perform a graceful failover of a node."""
        self.logger.info(f"Performing graceful failover of node {self.get_public_address(node)}...")
        self.run_command(f"docker exec -it mongo mongo --eval 'rs.stepDown()'")

    def add_user(self, username, password):
        """Add a user to MongoDB."""
        self.logger.info(f"Adding user {username} with password {password}...")
        command = (
            f"docker exec -it mongo mongo --eval 'db.createUser({{user: \"{username}\", pwd: \"{password}\", roles: [{{role: \"root\", db: \"admin\"}}]}})'"
        )
        self.run_command(command)

    def get_cluster_status(self):
        """Check the status of the MongoDB cluster."""
        self.logger.info("Checking MongoDB cluster status...")
        output = self.run_command("docker exec -it mongo mongo --eval 'rs.status()'")
        self.logger.info(output)


if __name__ == "__main__":
    cluster_manager = ClusterManager(username="admin", password="password", verbose=True)
    cluster_manager.setup_docker_cluster()
    cluster_manager.init_replica_set()
    for follower in cluster_manager.followers:
        cluster_manager.add_node_to_replica_set(follower)
    cluster_manager.rebalance_cluster()
    cluster_manager.add_user("testuser", "testpassword")
    cluster_manager.get_cluster_status()
