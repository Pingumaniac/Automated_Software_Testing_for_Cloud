import time
import logging
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
from datetime import timedelta

DEFAULT_SCOPE = "default_scope"
DEFAULT_COLLECTION = "default_collection"

class Operation:
    """ Operation superclass to be overridden with concrete operation types """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, operation_type=""):
        self.data_file_name = data_file_name
        self.cluster = cluster
        self.collection = collection
        self.verbose = verbose
        self.set_logger(prefix=operation_type)

    def execute(self):
        pass

    def get_data_file_name(self):
        return self.data_file_name

    def debug(self, msg):
        self.logger.debug(msg, extra=self.prefix)

    def info(self, msg):
        self.logger.info(msg, extra=self.prefix)

    def error(self, msg):
        self.logger.error(msg, extra=self.prefix)

    def set_logger(self, prefix=None):
        if not prefix:
            self.prefix = {'prefix': f'Operation'}
        else:
            self.prefix = {'prefix': prefix}
        self.logger = logging.getLogger(prefix)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(prefix)s - %(message)s')
        handler.setFormatter(formatter)
        for h in self.logger.handlers:
            self.logger.removeHandler(h)
        self.logger.addHandler(handler)


class N1QLQueryOperation(Operation):
    """ Operation representing a MongoDB query execution (read) """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, vandy_phrase="vanderbilt"):
        super().__init__(
            verbose=verbose,
            data_file_name=data_file_name,
            cluster=cluster,
            collection=collection,
            operation_type='Query')
        self.query = {"vandy_phrase": vandy_phrase}

    def execute(self):
        result = self.collection.find(self.query)
        return list(result)


class GetFullDocByKeyOperation(Operation):
    """ Operation representing an operation to get a full document by its key from MongoDB """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, doc_key=0):
        super().__init__(
            verbose=verbose,
            data_file_name=data_file_name,
            cluster=cluster,
            collection=collection,
            operation_type='GetFullDocByKey')
        self.key = doc_key

    def execute(self):
        response = self.collection.find_one({"_id": self.key})
        return response


class FullTextSearchOperation(Operation):
    """ Operation representing a full-text search (read) using MongoDB's text index """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, vandy_phrase="vanderbilt"):
        super().__init__(
            verbose=verbose,
            data_file_name=data_file_name,
            cluster=cluster,
            collection=collection,
            operation_type='FTS')
        self.query = {"$text": {"$search": vandy_phrase}}

    def execute(self):
        result = self.collection.find(self.query)
        return list(result)


class InsertOperation(Operation):
    """ Operation representing a document insertion into MongoDB """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, insert_doc=None, doc_key=0):
        super().__init__(
            verbose=verbose,
            data_file_name=data_file_name,
            cluster=cluster,
            collection=collection,
            operation_type='INSERT'
        )
        self.val = insert_doc
        self.val["_id"] = doc_key  # MongoDB requires the "_id" field to be the primary key

    def execute(self):
        response = None
        try:
            response = self.collection.insert_one(self.val)
        except DuplicateKeyError as e:
            self.error(f"Document with key {self.val['_id']} already exists.")
        return response


class UpdateOperation(Operation):
    """ Operation representing a document update (REPLACE) in MongoDB """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, doc_key=0, doc_replace_value=None):
        super().__init__(
            verbose=verbose,
            data_file_name=data_file_name,
            cluster=cluster,
            collection=collection,
            operation_type='UPDATE')
        self.key = doc_key
        self.val = doc_replace_value

    def execute(self):
        response = self.collection.replace_one({"_id": self.key}, self.val)
        return response


class DeleteOperation(Operation):
    """ Operation representing document deletion from MongoDB """
    def __init__(self, verbose=False, data_file_name="", cluster=None, collection=None, doc_key=0):
        super().__init__(
            verbose=verbose,
            data_file_name=data_file_name,
            cluster=cluster,
            collection=collection,
            operation_type="DELETE")
        self.key = doc_key

    def execute(self):
        response = self.collection.delete_one({"_id": self.key})
        return response


class OperationCommander:
    def __init__(self):
        self.n1ql_query_operations = []
        self.full_text_search_operations = []
        self.insert_operations = []
        self.delete_operations = []
        self.update_operations = []
        self.get_doc_by_key_operations = []

    def execute_operation(self, operation=None, record_operation_latency=False):
        """ Method to take in an operation and measure the time of its execution """
        start = time.time()
        operation.execute()
        end = time.time()
        diff = end - start

        if record_operation_latency:  # Save latency
            # Write this latency as a new line in the operation's designated file
            with open(operation.get_data_file_name(), 'a') as f:
                f.write(f'{diff}\n')
            if isinstance(operation, N1QLQueryOperation):
                self.n1ql_query_operations.append(operation)
            elif isinstance(operation, FullTextSearchOperation):
                self.full_text_search_operations.append(operation)
            elif isinstance(operation, InsertOperation):
                self.insert_operations.append(operation)
            elif isinstance(operation, UpdateOperation):
                self.update_operations.append(operation)
            elif isinstance(operation, DeleteOperation):
                self.delete_operations.append(operation)
            elif isinstance(operation, GetFullDocByKeyOperation):
                self.get_doc_by_key_operations.append(operation)
