# jwt-validator
This is a security library to validate JWT token issued by a spring-authorization-server that implements OAuth 2.1 and OpenID Connect 1.0 specifications.

## Use case
This library is used for securing access to api endpoints and also allowing access to certain health endpoints without requiring access-tokens.

## Workflow of Decoding a Jwt string token
The endpoints are assesed for jwt validation using the jwt issuer endpoints as defined in the configuration.

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
permitpath:
  - path: /users
    httpMethods: POST, GET
  - path: /user/create
    httpMethods: POST
  - path: /api/health/readiness
    httpMethods: GET
  - path: /api/health/readiness
    httpMethods: POST
  - path: /api/health/liveness
    httpMethods: HEAD, POST
  - path: /api/scope/read
    scopes: message:read      
```

If certain api endpoint requires a scope validation check then that can be specified as
 `scopes: message:read`. If both httpMethds and scopes is defined then the scopes will be applied only.

<br />
This jwt-validator can also request jwt token to be created or requested from the jwt-rest-service to be sent to a service that requires a jwt token.  This can be done
using the following configuration example:

```
jwtrequest:
  - in: /api/health/passheader
    out: /api/health/jwtreceiver
    jwt: request
  - in: /api/health/passheader
    out: /api/health/liveness
    jwt: forward
  - in: /api/health/forwardtoken
    out: /api/health/jwtreceiver
    jwt: forward
```
In the above first example of `in` and `out`, the `in` and `out` path is matched by the `ReactiveRequestContextHolder` web filter for a request inbound path and a another request that is going outbound.  If the in-path and out-path matches then a `request` will be made
to a jwt-rest-service to create a new jwt token.  

In the second example of `in` and `out`, if there is a jwt token in the inbound request then it will be `forward`ed to the downstream service.

This `jwt-validator` is meant to be deployed using a Eureka discovery service.  Therefore, this uses `loadbalanced` webclients.  The following is an example of how to configure the filter and the validator:
```
@Profile("!localdevtest")
@Configuration
public class WebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(WebClientConfig.class);
    @LoadBalanced
    @Bean
    public WebClient.Builder webClientBuilder() {
        LOG.info("returning load balanced webclient part");
        return WebClient.builder();
    }
    @LoadBalanced
    @Bean("noFilter")
    public WebClient.Builder webClientBuilderNoFilter() {
        LOG.info("returning for noFilter load balanced webclient part");
        return WebClient.builder();
    }

    @Bean
    public PublicKeyJwtDecoder publicKeyJwtDecoder() {
        return new PublicKeyJwtDecoder(webClientBuilderNoFilter());
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(webClientBuilderNoFilter());
    }

    @Bean
    public SimpleAuthenticationService simpleAuthenticationService() {
        return new SimpleAuthenticationService(webClientBuilder());
    }
}
```
The regular loadbalanced webclient will be used for the business service such as `SimpleAuthenticationService` or any other business service.  The `noFilter` beans are used by the `publicKeyJwtDecoder` and the `reactiveRequestContextHolder`.

Similarly, for testing the config can use non-loadbalanced webclient such as:
```
@Profile("localdevtest")
@Configuration
public class WebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(WebClientConfig.class);
    @Bean
    public WebClient.Builder webClientBuilder() {
        LOG.info("returning load balanced webclient part 2");
        return WebClient.builder();
    }
    @Bean
    public PublicKeyJwtDecoder publicKeyJwtDecoder() {
        return new PublicKeyJwtDecoder(webClientBuilder());
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(webClientBuilder());
    }

    @Bean
    public SimpleAuthenticationService userAccountService() {
        return new SimpleAuthenticationService(webClientBuilder());
    }
}
```

curl -X POST 'http://localhost:9000/oauth2/token?grant_type=client_credentials' \  
--header 'Authorization: Basic b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA=='
{"access_token":"eyJraWQiOiIxZDA2NmM0NS1hMDVmLTRhMjUtOWYwYS1hM2NiZTgxZmNmYWYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvYXV0aC1jbGllbnQiLCJhdWQiOiJvYXV0aC1jbGllbnQiLCJuYmYiOjE2ODM3NzEwOTAsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY4Mzc3MTM5MCwiaWF0IjoxNjgzNzcxMDkwfQ.d0pIwbTTF3NdMQ0x_ateveA551OuiLce7O0jKAzbmPpjTvXxq82RJVIHOdqW_MrRIW-yApt1HUE85wbPRS7C7KXYjuNeY73uva5KYNGGmGL__wokUvOQerohDv6PbLYupoIK3lx63OUYz3atSimXZ48tSHzdnNtMAh9Kw7sRE86UZLjzXk80WIQ5UNVY7_r6mwLrNiz_jjxEP2hW7HOCbR42bi3GL9u9veYR2p9nggDTwom8dN0zeIxGuWRbPPv4v8WPUlg8egUAEJadAiXC7LzEn_apvH_zkAx-ZRhqic4I_EdoWv7MUjyl0B4n2olvMeQwhM9S2OmnZDdrlNf8NQ","token_type":"Bearer","expires_in":299}%


Fore more on how to use this `jwt-validator` from github to another github repository follow [How to use maven library from github in your maven project?](https://sonamsamdupkhangsar.github.io/pulling-down-github-maven-library/)

