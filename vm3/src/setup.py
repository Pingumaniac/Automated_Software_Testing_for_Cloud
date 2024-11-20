import json
import argparse
from mongo_client import MongoClientManager  # Import your MongoDB client
from faker import Faker  # Used for generating random test data
class Setup:
    def __init__(self):
        # Faker for generating random documents
        self.fake = Faker()

    def build_hosts_json_file(self):
        """
        Generate hosts.json file with static configuration of MongoDB nodes.
        """
        # Static configuration of MongoDB nodes
        hosts = {
            'hosts': [
                {'name': 'vm1', 'public': '192.168.5.56', 'private': '10.0.0.1'},
                {'name': 'vm2', 'public': '192.168.5.211', 'private': '10.0.0.2'},
                {'name': 'vm3', 'public': '192.168.5.68', 'private': '10.0.0.3'},
                {'name': 'vm4', 'public': '192.168.5.25', 'private': '10.0.0.4'}
            ]
        }
        with open('src/hosts.json', 'w') as f:
            json.dump(hosts, f, indent=2)
        print('Successfully created src/hosts.json!')

    def generate_random_documents(self, num_docs=500):
        """
        Generate random documents for MongoDB.
        """
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
        """
        Insert random test data into MongoDB.
        """
        # MongoDB replica set URI
        db_client = MongoClientManager(uri="mongodb://192.168.5.211:27017,192.168.5.68:27017,192.168.5.25:27017/?replicaSet=rs0")
        db_client.connect()
        documents = self.generate_random_documents(num_docs)
        for document in documents:
            db_client.insert_one(collection_name, document)
        print(f'Successfully inserted {num_docs} documents into MongoDB replica set.')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup script for MongoDB and FastAPI.')
    parser.add_argument('--generate-hosts', action='store_true', help='Generate hosts.json file with static MongoDB configuration.')
    parser.add_argument('--insert-data', action='store_true', help='Insert test data into MongoDB.')

    args = parser.parse_args()

    setup = Setup()

    if args.generate_hosts:
        setup.build_hosts_json_file()

    if args.insert_data:
        setup.insert_test_data()
