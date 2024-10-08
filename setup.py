import subprocess
import json
import argparse
import os
import openstack
from src.mongo_client import MongoDBClient  # Import your MongoDB client
from faker import Faker  # Used for generating random test data

class Setup:
    def __init__(self):
        # Initialize OpenStack connection to Chameleon Cloud
        self.conn = openstack.connect(cloud='chameleon')

        # Faker for generating random documents
        self.fake = Faker()

    def get_instance_addresses(self):
        """Return a list of dicts {'public_ip': '', 'private_ip': ''} for each Chameleon Cloud instance."""
        instances = self.conn.compute.servers()
        addresses = []

        for instance in instances:
            server_details = self.conn.compute.get_server(instance.id)
            addresses.append({
                'name': instance.name,
                'public': server_details.public_v4 or server_details.public_v6,
                'private': server_details.private_v4 or None,
            })
        return addresses

    def run_ansible_playbook(self):
        """Run ansible playbook to install and start MongoDB on provided hosts."""
        playbook_cmd = "ansible-playbook -i hosts.ini mongo-playbook.yml"
        os.environ['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
        print(f'Running playbook with ansible: `{playbook_cmd}`')
        process = subprocess.Popen(playbook_cmd.split())
        output, error = process.communicate()
        if error:
            print(f'Error: {error}')
        else:
            print(output)

    def build_hosts_json_file(self):
        """Generate hosts.json using instance details from Chameleon Cloud."""
        hosts = {'hosts': self.get_instance_addresses()}
        with open('src/hosts.json', 'w') as f:
            json.dump(hosts, f, indent=2)
        print('Successfully created src/hosts.json!')

    def generate_random_documents(self, num_docs=500):
        """Generate random documents for MongoDB."""
        documents = []
        for _ in range(num_docs):
            documents.append({
                'name': self.fake.name(),
                'email': self.fake.email(),
                'address': self.fake.address(),
                'created_at': self.fake.date_time_this_year()
            })
        return documents

    def insert_test_data(self, collection_name='testdata', num_docs=500):
        """Insert random test data into MongoDB."""
        db_client = MongoDBClient()  # Assuming MongoDBClient is set up to connect to your MongoDB instance
        db_client.connect()
        documents = self.generate_random_documents(num_docs)
        db_client.insert_one(collection_name, documents)
        print(f'Successfully inserted {num_docs} documents into MongoDB.')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup script for MongoDB and FastAPI.')
    parser.add_argument('--generate-hosts', action='store_true', help='Generate hosts.json file for Chameleon Cloud instances.')
    parser.add_argument('--run-ansible', action='store_true', help='Run ansible playbook to install MongoDB.')
    parser.add_argument('--insert-data', action='store_true', help='Insert test data into MongoDB.')

    args = parser.parse_args()

    setup = Setup()

    if args.generate_hosts:
        setup.build_hosts_json_file()

    if args.run_ansible:
        setup.run_ansible_playbook()

    if args.insert_data:
        setup.insert_test_data()
