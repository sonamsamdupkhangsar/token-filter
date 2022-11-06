# email-rest-service

This is a template for building Spring Webflux reactive Java webservice api.

## Run locally

`mvn spring-boot:run -Dspring-boot.run.arguments="--EMAIL_HOST=<HOST> \
 --EMAIL_PORT=<PORT> \
 --EMAIL_USERNAME=<USERNAME> \
 --EMAIL_PASSWORD=<PASSWORD>"`
 
 
## Build Docker image

Build docker image using included Dockerfile.


`docker build -t imageregistry/project-rest-service:1.0 .` 

## Push Docker image to repository

`docker push imageregistry/project-rest-service:1.0`

## Deploy Docker image locally

`docker run -e EMAIL_HOST=<HOST> -e EMAIL_PORT=<PORT> \
 -e EMAIL_USERNAME=<EMAIL> -e EMAIL_PASSWORD=<PASSWORD> \
 --publish 8080:8080 imageregistry/project-rest-service:1.0`

Test project api using `curl`:

````
 curl -X POST http://localhost:8080/project -H 'Content-Type: application/json' \
 -d '{"from": "from@my.email", "to": "to@my.email", \
  "subject":"hello", "body": "welcome to planet Earth"}'
 ```` 

## Installation on Kubernetes
Use a Helm chart from here @ [sonam-helm-chart](https://github.com/sonamsamdupkhangsar/sonam-helm-chart):

```helm install projectapi sonam/mychart -f values.yaml --version 0.1.11 --namespace=yournamespace```

