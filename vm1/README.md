## Complete Instructions to Set Up System

1. Follow [this](k8s/README.md) to set up MongoDB pods.

Now, we will set up the Docker image that runs the Mongo client code.

2. Login to Docker. To create an account or find your username and password, go here: https://app.docker.com/
```
docker login -u '<user> -p "<password>" docker.io
```
3. Navigate to Docker image in `/vm1/app/`

4. Change the client code as needed by modifying `test.py`
5. Ensure all dependencies are copied in `Dockerfile` (so far just copying `test.py`)
5. Build Docker image from `/vm1/app/`
```
docker build -t <user>/pymongo .
```
7. Check Docker build is listed
```
docker image ls
```
8. Push image to Docker repository
```
 docker push <user>/pymongo
```
9. Configure the user to your username in line 8 in `k8s/pymongo-deployment.yaml`
10. Run the pod
```
kubectl apply -f pymongo-deployment.yaml
```
11. Monitor the pod status
```
kubectl get pods -w
```
12. The pod should complete after a while. Debug with these two commands:
```
kubectl describe po python-mongo-client
kubectl logs python-mongo-client
```
13. The test connection code provided in `test.py` log should show the following:
```
cc@vm1:~/final_project/k8s$ kubectl logs python-mongo-client
Connected to MongoDB!
Databases: ['admin', 'config', 'local']
Writing to test_db...
Inserted document with _id: 673e33b64fb7ae1a4d85c6aa
```
14. Check record shows up in the primary node of the database
```
kubectl exec -it mongo-1 -- mongo
...
rs0:PRIMARY> use test_db
switched to db test_db
rs0:PRIMARY> show collections
test_col
rs0:PRIMARY> db.test_col.find()
{ "_id" : ObjectId("673e33b64fb7ae1a4d85c6aa"), "name" : "test", "value" : 123 }
rs0:PRIMARY> exit
```

15. Note: You can test your docker container interactively (with -it option).
```
docker run -it pingumaniac/pymongo:main /bin/bash
```

16. You can test in kubernetes interactively

- **Get help:**
```
kubectl exec -it --help
```

- **Access the Pod:**
```
kubectl exec -it python-mongo-client -- /bin/bash
```

- **Run the Python codes inside the pod sequentially:**
```
python3 test.py
python3 database_setup.py
python3 test_unit.py
python3 test_atheris.py
python3 plot_metrics_unit.py
python3 plot_metrics_atheris.py
```

- **Exit the Pod:**
```
exit
```
