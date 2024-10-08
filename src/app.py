from fastapi import FastAPI, HTTPException
from mongo_client import MongoClientManager
from operations import N1QLQueryOperation, GetFullDocByKeyOperation, InsertOperation, UpdateOperation, DeleteOperation
from data_manager import DataManager
from cluster_manager import ClusterManager
from random_json_generator import RandomJSONGenerator

app = FastAPI()

# Instantiate the necessary components
mongo_client_manager = MongoClientManager()
data_manager = DataManager(username="admin", password="password", leader_address="localhost", verbose=True)
cluster_manager = ClusterManager(username="admin", password="password", verbose=True)
random_json_generator = RandomJSONGenerator(verbose=True)

@app.post("/mongo/insert")
def insert_document(key: int):
    try:
        doc = random_json_generator.generate_random_json_document()
        insert_op = InsertOperation(
            verbose=True,
            cluster=mongo_client_manager.client,
            collection=mongo_client_manager.db["test_collection"],
            insert_doc=doc,
            doc_key=key
        )
        result = data_manager.database_operation_commander.execute_operation(insert_op)
        return {"message": "Document inserted", "result": str(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/mongo/find")
def find_document(key: int):
    try:
        find_op = GetFullDocByKeyOperation(
            verbose=True,
            cluster=mongo_client_manager.client,
            collection=mongo_client_manager.db["test_collection"],
            doc_key=key
        )
        result = data_manager.database_operation_commander.execute_operation(find_op)
        return {"message": "Document found", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cluster/start")
def start_cluster():
    try:
        result = cluster_manager.setup_docker_cluster()
        return {"message": "Cluster started", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cluster/stop")
def stop_cluster():
    try:
        result = cluster_manager.run_command("docker-compose down")
        return {"message": "Cluster stopped", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
