# Instructions for Executing the Source Code

This directory contains all the necessary scripts to manage and interact with MongoDB clusters, run tests, and generate random data.

## Execution Instructions

### **Step 1: Generate Hosts Configuration**
Generate `hosts.json` (if not already generated) using the `setup.py` script:
```
python setup.py --generate-hosts
```

### **Step 2: Start FastAPI Server**
Start the FastAPI server for MongoDB interaction:
```
python3 app.py
```

## **Step 3: Perform MongoDB Operations**
Use the REST API endpoints provided by app.py:
* Insert Document:
```
curl -X POST "http://192.168.5.68:8000/mongo/insert" -H "Content-Type: application/json" -d '{"key": 1}'
```

* Find Document:
```
curl -X GET "http://192.168.5.68:8000/mongo/find?key=1"
```

## Notes
* Ensure that hosts.json contains the correct IPs for all VMs.
* Use random_json_generator.py to create custom test data if needed.
