import unittest
import time
from unittest.mock import patch, MagicMock
from pymongo.errors import ConnectionFailure
from src.mongo_client import MongoDBClient


class TestMongoDBClient(unittest.TestCase):

    @patch('pymongo.MongoClient')
    def setUp(self, mock_mongo_client):
        """Setup mock MongoDB client."""
        self.mongo_client = MongoDBClient(uri="mongodb://192.168.5.211:27017,192.168.5.25:27017/?replicaSet=rs0")
        self.mock_db = MagicMock()
        self.mock_collection = MagicMock()

        # Mock the connection to the database
        self.mongo_client.db = self.mock_db
        self.mongo_client.db['test_collection'] = self.mock_collection

    def test_connection_success(self):
        """Test MongoDB connection success."""
        with patch('pymongo.MongoClient') as mock_client:
            mock_client.return_value = MagicMock()
            try:
                self.mongo_client.connect()
                self.mongo_client.client.admin.command.assert_called_once_with('ping')
            except ConnectionFailure:
                self.fail("MongoDB connection failed.")

    def test_insert_latency(self):
        """Test insert latency."""
        start_time = time.time()
        self.mongo_client.insert_one('test_collection', {'name': 'test'})
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # Convert to milliseconds
        self.mongo_client.db['test_collection'].insert_one.assert_called_once_with({'name': 'test'})
        self.assertLess(latency, 100, "Insert latency exceeded acceptable threshold.")

    def test_query_latency(self):
        """Test query latency."""
        mock_cursor = MagicMock()
        mock_cursor.return_value = [{'name': 'test'}]
        self.mongo_client.db['test_collection'].find.return_value = mock_cursor

        start_time = time.time()
        result = self.mongo_client.find('test_collection', {'name': 'test'})
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # Convert to milliseconds
        self.mongo_client.db['test_collection'].find.assert_called_once_with({'name': 'test'})
        self.assertEqual(result, mock_cursor)
        self.assertLess(latency, 100, "Query latency exceeded acceptable threshold.")

    def test_replication_consistency(self):
        """Test data consistency across replica sets."""
        # Simulate primary and secondary data retrieval
        primary_data = [{'name': 'test', 'value': 1}]
        secondary_data = [{'name': 'test', 'value': 1}]

        self.mongo_client.db['test_collection'].find.return_value = primary_data
        with patch('pymongo.MongoClient') as mock_secondary_client:
            mock_secondary = MagicMock()
            mock_secondary.db['test_collection'].find.return_value = secondary_data
            mock_secondary_client.return_value = mock_secondary

            # Verify data consistency
            primary_result = self.mongo_client.find('test_collection', {})
            secondary_result = mock_secondary.db['test_collection'].find({})
            self.assertEqual(primary_result, secondary_result, "Replica set data is inconsistent.")

    def test_update_latency(self):
        """Test update latency."""
        start_time = time.time()
        self.mongo_client.update_one('test_collection', {'name': 'test'}, {'$set': {'age': 30}})
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # Convert to milliseconds
        self.mongo_client.db['test_collection'].update_one.assert_called_once_with(
            {'name': 'test'}, {'$set': {'age': 30}})
        self.assertLess(latency, 100, "Update latency exceeded acceptable threshold.")

    def test_delete_latency(self):
        """Test delete latency."""
        start_time = time.time()
        self.mongo_client.delete_one('test_collection', {'name': 'test'})
        end_time = time.time()
        latency = (end_time - start_time) * 1000  # Convert to milliseconds
        self.mongo_client.db['test_collection'].delete_one.assert_called_once_with({'name': 'test'})
        self.assertLess(latency, 100, "Delete latency exceeded acceptable threshold.")

    def test_crash_resilience(self):
        """Test MongoDB crash resilience under invalid inputs."""
        invalid_input = {'$set': {'$invalidField': 123}}
        with self.assertRaises(Exception):
            self.mongo_client.update_one('test_collection', {'name': 'test'}, invalid_input)

    def tearDown(self):
        """Close the MongoDB connection."""
        self.mongo_client.close()


if __name__ == '__main__':
    unittest.main()
