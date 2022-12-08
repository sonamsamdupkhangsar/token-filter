# jwt-validator
This is a security library to validate JWT token issued using the [jwt-issuer](https://github.com/sonamsamdupkhangsar/jwt-issuer) library.

## Use case
This library is used for securing access to a web based application by requiring all request to contain a JWT token.  This library will inspect all request for a JWT string token.  

## Workflow of Decoding a Jwt string token
`PublicKeyJwtDecoder.class` will take the Jwt string.  It will parse the `keyId` of the Jwt token to get the id of the KeyPair.  It will make a request to fetch the RSA public-key from another rest-service like [jwt-rest-service](https://github.com/sonamsamdupkhangsar/jwt-rest-service) that uses the `PublicKeyJwtCreator.class` for creating the Jwt token and which stores the RSA key-pair. 
 
 The validator service will then use the public key to validate the token has not been tampered and return a OAuth2 JWT token type.
  
 ## Token Validator
 Token validators should use the library provided here for securing web app.

 ## Building package
 `mvn -s settings.xml clean package`
 Use the settings.xml file included and specify the personal token in a environment variable for PERSONAL_ACCESS_TOKEN as `export PERSONAL_ACCESS_TOKEN=1234-dummy-value`
 
 The `deploy.yml` in building maven package does this.
 
## How to use this in your Spring Maven based project
To use this `jwt-validator` in your maven based project include the following in your pom.xml as:
```
<dependency>
  <groupId>me.sonam</groupId>
  <artifactId>jwt-validator</artifactId>
  <version>1.0-SNAPSHOT</version>
</dependency>
```

Then in your class you have to enable component scan as following to pick up this security library package:

``` 
@ComponentScan(basePackages = {"me.sonam.security"})
```

or do

```
@SpringBootApplication(scanBasePackages = {"me.sonam", "include.your.app.base.code.package.also.if.needed."})
```

You also have to ensure your application is scanned too.  So you may have to add additional package to scan as well as shown above.


You can override permitted paths that don't require jwt validation in your application.yaml as following:
```
permitPaths: /api/health/*
```
<br />

Fore more on how to use this `jwt-validator` from github to another github repository follow [How to use maven library from github in your maven project?](https://sonamsamdupkhangsar.github.io/pulling-down-github-maven-library/)

