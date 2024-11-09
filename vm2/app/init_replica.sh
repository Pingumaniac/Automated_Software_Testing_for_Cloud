#!/bin/bash

# This script initializes vm4 as a secondary in the MongoDB replica set.
mongo --eval 'rs.add("192.168.5.25:27017")'  # IP of vm4
