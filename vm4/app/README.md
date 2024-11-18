## Instructions

To retrieve the MongoDB Docker container, run `sudo bash install_mongodb_image.sh`

We have installed docker image through `docker build -t vm4-image -f Dockerfile .`


You can create and run the docker container through
`docker run -d --name vm4-container -p 27017:27017 vm4-image`
