from pymongo import MongoClient

client = MongoClient('mongodb://mongo.default.svc.cluster.local:27017/?replicaSet=rs0')

print("Connected to MongoDB!")
print("Databases:", client.list_database_names())

print("Writing to test_db...")
db = client['test_db']
collection = db['test_col']
test_document = {"name": "test", "value": 123}
insert_result = collection.insert_one(test_document)

print(f"Inserted document with _id: {insert_result.inserted_id}")