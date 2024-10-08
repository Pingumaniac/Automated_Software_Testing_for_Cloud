import subprocess
import logging
import os
from pymongo import MongoClient, ASCENDING
from pymongo.errors import OperationFailure
from pathlib import Path
from operations import InsertOperation, UpdateOperation, DeleteOperation, OperationCommander
from random_json_generator import RandomJSONGenerator
from yaspin import yaspin

DEFAULT_SCOPE = "default_scope"
DEFAULT_COLLECTION = "default_collection"

class DataManager:
    def __init__(self, username="", password="", verbose=False, leader_address="localhost"):
        self.username = username
        self.password = password
        self.verbose = verbose
        self.setup_logging(verbose=verbose)
        self.leader_address = leader_address
        self.random_json_generator = RandomJSONGenerator()
        self.database_operation_commander = OperationCommander()

        # Set up MongoDB connection
        self.mongo_url = f"mongodb://{self.username}:{self.password}@{self.leader_address}:27017"
        self.client = MongoClient(self.mongo_url)
        self.db = self.client['benchmarkdb']  # Default MongoDB database
        self.collection = self.db[DEFAULT_COLLECTION]  # Default collection

    def setup_logging(self, verbose=False):
        """ Set up logging. """
        self.logger = logging.getLogger('DataManager')
        formatter = logging.Formatter('%(prefix)s - %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.prefix = {'prefix': 'Data Manager'}
        self.logger.addHandler(handler)
        self.logger = logging.LoggerAdapter(self.logger, self.prefix)
        if verbose:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug('Debug mode enabled', extra=self.prefix)
        else:
            self.logger.setLevel(logging.INFO)

    def debug(self, msg):
        self.logger.debug(msg, extra=self.prefix)

    def info(self, msg):
        self.logger.info(msg, extra=self.prefix)

    def error(self, msg):
        self.logger.error(msg, extra=self.prefix)

    def create_primary_index(self, collection_name=""):
        """ Create an index on the specified collection """
        self.info(f'Creating primary index on `{collection_name}`')
        collection = self.db[collection_name]
        try:
            collection.create_index([("key", ASCENDING)], unique=True)
            self.info(f'Primary index created on `{collection_name}`')
        except OperationFailure as e:
            self.error(f'Error creating index: {e}')
            return None

    def create_collection(self, collection_name=""):
        """ Create a new collection in MongoDB """
        self.info(f'Creating collection `{collection_name}`')
        self.db.create_collection(collection_name)
        self.info(f'Collection `{collection_name}` created')

    def drop_collection(self, collection_name=""):
        """ Drop a collection from the database """
        self.info(f'Dropping collection `{collection_name}`')
        self.db.drop_collection(collection_name)
        self.info(f'Collection `{collection_name}` dropped')

    def insert_documents(self, collection_name="", num_docs=1000):
        """ Insert a specified number of documents into a collection """
        self.info(f'Inserting {num_docs} documents into `{collection_name}`')
        collection = self.db[collection_name]
        docs = [self.random_json_generator.generate_random_json_document() for _ in range(num_docs)]
        collection.insert_many(docs)
        self.info(f'Successfully inserted {num_docs} documents')

    def update_documents(self, collection_name="", num_docs=1000):
        """ Update a specified number of documents in a collection """
        self.info(f'Updating {num_docs} documents in `{collection_name}`')
        collection = self.db[collection_name]
        for i in range(num_docs):
            query = {"_id": i}
            new_values = {"$set": {"updated_field": f"new_value_{i}"}}
            collection.update_one(query, new_values)
        self.info(f'Successfully updated {num_docs} documents')

    def delete_documents(self, collection_name="", num_docs=1000):
        """ Delete a specified number of documents from a collection """
        self.info(f'Deleting {num_docs} documents from `{collection_name}`')
        collection = self.db[collection_name]
        for i in range(num_docs):
            query = {"_id": i}
            collection.delete_one(query)
        self.info(f'Successfully deleted {num_docs} documents')

    def run_inserts(self, collection_name="", num_docs=1000):
        """ Run a batch of insert operations with the OperationCommander """
        self.info(f'Running {num_docs} insert operations...')
        with yaspin().white.bold.shark.on_blue as sp:
            for i in range(num_docs):
                self.database_operation_commander.execute_operation(
                    InsertOperation(
                        verbose=self.verbose,
                        cluster=self.client,
                        collection=self.db[collection_name],
                        insert_doc=self.random_json_generator.generate_random_json_document(),
                        doc_key=i
                    )
                )

    def run_updates(self, collection_name="", num_docs=100):
        """ Run a batch of update operations with the OperationCommander """
        self.info(f'Running {num_docs} update operations...')
        with yaspin().white.bold.shark.on_blue as sp:
            for i in range(num_docs):
                self.database_operation_commander.execute_operation(
                    UpdateOperation(
                        verbose=self.verbose,
                        cluster=self.client,
                        collection=self.db[collection_name],
                        doc_key=i,
                        new_value=f"updated_value_{i}"
                    )
                )

    def run_deletes(self, collection_name="", num_docs=100):
        """ Run a batch of delete operations with the OperationCommander """
        self.info(f'Running {num_docs} delete operations...')
        with yaspin().white.bold.shark.on_blue as sp:
            for i in range(num_docs):
                self.database_operation_commander.execute_operation(
                    DeleteOperation(
                        verbose=self.verbose,
                        cluster=self.client,
                        collection=self.db[collection_name],
                        doc_key=i
                    )
                )


if __name__ == "__main__":
    data_manager = DataManager(username="admin", password="password", verbose=True)
    data_manager.create_collection("test_collection")
    data_manager.insert_documents("test_collection", num_docs=100)
    data_manager.update_documents("test_collection", num_docs=50)
    data_manager.delete_documents("test_collection", num_docs=50)
