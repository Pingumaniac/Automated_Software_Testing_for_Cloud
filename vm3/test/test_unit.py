import unittest
from unittest.mock import patch, MagicMock
from pymongo.errors import ConnectionFailure
from src.mongo_client import MongoDBClient

class TestMongoDBClient(unittest.TestCase):

    @patch('pymongo.MongoClient')
    def setUp(self, mock_mongo_client):
        # Create an instance of MongoDBClient
        self.mongo_client = MongoDBClient()
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

    def test_insert_one(self):
        """Test insert_one method."""
        self.mongo_client.insert_one('test_collection', {'name': 'test'})
        self.mongo_client.db['test_collection'].insert_one.assert_called_once_with({'name': 'test'})

    def test_find(self):
        """Test find method."""
        # Mock the return value of find
        mock_cursor = MagicMock()
        mock_cursor.return_value = [{'name': 'test'}]
        self.mongo_client.db['test_collection'].find.return_value = mock_cursor

        result = self.mongo_client.find('test_collection', {'name': 'test'})
        self.mongo_client.db['test_collection'].find.assert_called_once_with({'name': 'test'})
        self.assertEqual(result, mock_cursor)

    def test_update_one(self):
        """Test update_one method."""
        self.mongo_client.update_one('test_collection', {'name': 'test'}, {'$set': {'age': 30}})
        self.mongo_client.db['test_collection'].update_one.assert_called_once_with(
            {'name': 'test'}, {'$set': {'age': 30}})

    def test_delete_one(self):
        """Test delete_one method."""
        self.mongo_client.delete_one('test_collection', {'name': 'test'})
        self.mongo_client.db['test_collection'].delete_one.assert_called_once_with({'name': 'test'})

    def tearDown(self):
        self.mongo_client.close()


if __name__ == '__main__':
    unittest.main()
