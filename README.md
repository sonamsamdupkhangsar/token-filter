# jwt-spring-security
This is a security library that will issue Oauth2 type of JWT token and also provide a library api to validate it using a RSA public key.

The intention is that a service like a [jwt-rest-service](https://github.com/sonamsamdupkhangsar/jwt-rest-service) will use this library to issue a JWT token.  
The microservice that intend to expose api will allow access and validate the user via JWT token with that public key using this library.
  
## Use case
This library is used for securing access to a web based application by requiring all request to contain a JWT token.  This library will inspect all request for a JWT string token.  

## Workflow of Decoding a Jwt string token
`PublicKeyJwtDecoder.class` will take the Jwt string.  It will parse the `keyId` of the Jwt token to get the id of the KeyPair.  It will make a request to fetch the RSA public-key from another rest-service like `jwt-rest-service` that uses the `PublicKeyJwtCreator.class` from this library that creates the Jwt token and which stores the RSA key-pair used for token generation. 
 
 The validator service will then use the public key to validate the token has not been tampered and return a OAuth2 JWT token type.
 
 ## Token Creator
 Token generator should use the `PublicKeyJwtCreator.class` to generate and store the RSA public key pair in their repository.
 
 ## Token Validator
 Token validators should use the library provided here for securing web app.
 

  