# database_setup.py

from pymongo import MongoClient
from bson.objectid import ObjectId
import uuid
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseManager:
    """Manages the connection to the MongoDB database."""
    def __init__(self, uri, db_name):
        self.uri = uri
        self.db_name = db_name
        self.client = None
        self.db = None

    def connect(self):
        """Establishes a connection to MongoDB."""
        try:
            self.client = MongoClient(self.uri)
            self.db = self.client[self.db_name]
            logging.info("Connected to MongoDB!")
            logging.info(f"Databases: {self.client.list_database_names()}")
        except Exception as e:
            logging.error(f"Failed to connect to MongoDB: {e}")
            raise

    def get_collection(self, collection_name):
        """Retrieves a collection from the database."""
        if self.db is not None:
            return self.db[collection_name]
        else:
            logging.error("Database connection is not established.")
            raise Exception("Database connection is not established.")

class AccountManager:
    """Handles operations related to the Account collection."""
    def __init__(self, db_manager):
        self.collection = db_manager.get_collection('Account')

    def create_account(self, is_admin=False):
        """Creates a new account."""
        account = {
            "accountID": str(uuid.uuid4()),
            "isAdmin": is_admin,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        try:
            result = self.collection.insert_one(account)
            logging.info(f"Inserted Account with _id: {result.inserted_id}")
            return account
        except Exception as e:
            logging.error(f"Failed to insert Account: {e}")
            raise

class UserManager:
    """Handles operations related to the User collection."""
    def __init__(self, db_manager):
        self.collection = db_manager.get_collection('User')

    def create_user(self, account_id, name, birthday, nationality, gender, ethnicity):
        """Creates a new user linked to an account."""
        user = {
            "accountID": account_id,
            "name": name,
            "birthday": birthday,
            "nationality": nationality,
            "gender": gender,
            "ethnicity": ethnicity,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        try:
            result = self.collection.insert_one(user)
            logging.info(f"Inserted User with _id: {result.inserted_id}")
            return user
        except Exception as e:
            logging.error(f"Failed to insert User: {e}")
            raise

class AdminManager:
    """Handles operations related to the Admin collection."""
    def __init__(self, db_manager):
        self.collection = db_manager.get_collection('Admin')

    def create_admin(self, account_id, name, birthday, nationality, gender, ethnicity, role):
        """Creates a new admin linked to an account."""
        admin = {
            "accountID": account_id,
            "name": name,
            "birthday": birthday,
            "nationality": nationality,
            "gender": gender,
            "ethnicity": ethnicity,
            "role": role,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        try:
            result = self.collection.insert_one(admin)
            logging.info(f"Inserted Admin with _id: {result.inserted_id}")
            return admin
        except Exception as e:
            logging.error(f"Failed to insert Admin: {e}")
            raise

class MessageManager:
    """Handles operations related to the Messages collection."""
    def __init__(self, db_manager):
        self.collection = db_manager.get_collection('Messages')

    def create_message(self, sender_id, receiver_id, content, status="Sent", read_time=None):
        """Creates a new message between two accounts."""
        message = {
            "senderID": sender_id,
            "receiverID": receiver_id,
            "content": content,
            "sent_time": datetime.utcnow(),
            "read_time": read_time,
            "status": status,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        try:
            result = self.collection.insert_one(message)
            logging.info(f"Inserted Message with _id: {result.inserted_id}")
            return message
        except Exception as e:
            logging.error(f"Failed to insert Message: {e}")
            raise

class RandomDataGenerator:
    """Generates random data for users and admins."""
    @staticmethod
    def generate_user_data():
        """Generates sample user data."""
        return {
            "name": "User_" + str(uuid.uuid4())[:8],
            "birthday": datetime(1990, 1, 1),
            "nationality": "American",
            "gender": "Male",
            "ethnicity": "Ethnicity1"
        }

    @staticmethod
    def generate_admin_data():
        """Generates sample admin data."""
        return {
            "name": "Admin_" + str(uuid.uuid4())[:8],
            "birthday": datetime(1985, 5, 15),
            "nationality": "Canadian",
            "gender": "Female",
            "ethnicity": "Ethnicity2",
            "role": "Moderator"
        }

def main():
    # MongoDB connection URI (update if different)
    mongo_uri = 'mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0'
    db_name = 'test_db'

    # Initialize Database Manager
    db_manager = DatabaseManager(mongo_uri, db_name)
    db_manager.connect()

    # Initialize Collection Managers
    account_manager = AccountManager(db_manager)
    user_manager = UserManager(db_manager)
    admin_manager = AdminManager(db_manager)
    message_manager = MessageManager(db_manager)

    # Generate and Insert Accounts, Users, and Admins
    # Insert Two Users
    user_data_1 = RandomDataGenerator.generate_user_data()
    account_user_1 = account_manager.create_account(is_admin=False)
    user_1 = user_manager.create_user(
        account_id=account_user_1['accountID'],
        name=user_data_1['name'],
        birthday=user_data_1['birthday'],
        nationality=user_data_1['nationality'],
        gender=user_data_1['gender'],
        ethnicity=user_data_1['ethnicity']
    )

    user_data_2 = RandomDataGenerator.generate_user_data()
    account_user_2 = account_manager.create_account(is_admin=False)
    user_2 = user_manager.create_user(
        account_id=account_user_2['accountID'],
        name=user_data_2['name'],
        birthday=user_data_2['birthday'],
        nationality=user_data_2['nationality'],
        gender=user_data_2['gender'],
        ethnicity=user_data_2['ethnicity']
    )

    # Insert Two Admins
    admin_data_1 = RandomDataGenerator.generate_admin_data()
    account_admin_1 = account_manager.create_account(is_admin=True)
    admin_1 = admin_manager.create_admin(
        account_id=account_admin_1['accountID'],
        name=admin_data_1['name'],
        birthday=admin_data_1['birthday'],
        nationality=admin_data_1['nationality'],
        gender=admin_data_1['gender'],
        ethnicity=admin_data_1['ethnicity'],
        role=admin_data_1['role']
    )

    admin_data_2 = RandomDataGenerator.generate_admin_data()
    account_admin_2 = account_manager.create_account(is_admin=True)
    admin_2 = admin_manager.create_admin(
        account_id=account_admin_2['accountID'],
        name=admin_data_2['name'],
        birthday=admin_data_2['birthday'],
        nationality=admin_data_2['nationality'],
        gender=admin_data_2['gender'],
        ethnicity=admin_data_2['ethnicity'],
        role=admin_data_2['role']
    )

    # Insert Messages Between Users
    message_user_1_to_user_2 = message_manager.create_message(
        sender_id=account_user_1['accountID'],
        receiver_id=account_user_2['accountID'],
        content="hello",
        status="Sent"
    )

    message_user_2_to_user_1 = message_manager.create_message(
        sender_id=account_user_2['accountID'],
        receiver_id=account_user_1['accountID'],
        content="hi",
        status="Sent"
    )

    # Insert Messages Between Admins
    message_admin_1_to_admin_2 = message_manager.create_message(
        sender_id=account_admin_1['accountID'],
        receiver_id=account_admin_2['accountID'],
        content="good morning",
        status="Sent"
    )

    message_admin_2_to_admin_1 = message_manager.create_message(
        sender_id=account_admin_2['accountID'],
        receiver_id=account_admin_1['accountID'],
        content="good morning!",
        status="Sent"
    )

    logging.info("Successfully inserted all users, admins, and messages.")

if __name__ == "__main__":
    main()
