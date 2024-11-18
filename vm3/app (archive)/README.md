## Instructions

To retrieve the MongoDB Docker container, run `sudo bash install_mongodb_image.sh`

We have installed docker image through `docker build -t vm3-image -f Dockerfile .`


You can create and run the docker container through
`docker run -d --name vm3-container -p 5000:5000 vm3-image`
