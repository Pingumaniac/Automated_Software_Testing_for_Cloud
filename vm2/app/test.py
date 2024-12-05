# Import the MongoClient class from the pymongo library to interact with MongoDB.
from pymongo import MongoClient

# Create a MongoDB client instance connecting to the specified MongoDB URI with a replica set.
client = MongoClient('mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0')

# Print a confirmation message indicating a successful connection to MongoDB.
print("Connected to MongoDB!")

# List and print all the databases available in the connected MongoDB instance.
print("Databases:", client.list_database_names())

# Print a message indicating the start of writing to the 'test_db' database.
print("Writing to test_db...")

# Access or create a database named 'test_db'.
db = client['test_db']

# Access or create a collection named 'test_col' within the 'test_db' database.
collection = db['test_col']

# Define a sample document to be inserted into the 'test_col' collection.
test_document = {"name": "test", "value": 123}

# Insert the sample document into the collection and store the result of the insertion operation.
insert_result = collection.insert_one(test_document)

# Print the ID of the inserted document to confirm successful insertion.
print(f"Inserted document with _id: {insert_result.inserted_id}")
