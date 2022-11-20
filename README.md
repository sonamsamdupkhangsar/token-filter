# spring-security-jwt
This is a security library that will create a (Oauth2) JWT token and also provide a library api to validate it using a RSA public key.

The intention is that a service like a `jwt-rest-service` will use this library to issue a JWT token.  
The microservice that intend to expose api will allow access and validate the user via JWT token with that public key.
  