# token-filter
This `token-filter` is a library for allowing access to endpoints by specifying their paths in a property file such as:
```
permitpath:
  - path: /api/health/readiness
    httpMethods: GET, POST
  - path: /api/scope/callread
    httpMethods: GET
  - path: /api/scope/read
    scopes: message.read, message.write    
```
It can also enforce that paths contain Oauth2 scopes within the access-token as well.
In the above example the first "health" endpoint will be permitted for GET and POST Http methods.  However, the path `/api/scope/read` will require those 2 scopes in jwt token.

This token-filter library can filter or forward the access-token to downstream services.  It can also request access-token to be created from the spring authorization server using `Client Credentials Flow` token.  This can be done
using the following configuration example:

```
jwtrequest:
  - in: /api/scope/callread
    out: /api/scope/read
    accessToken:
      option: request
      scopes: message.read
      base64EncodedClientIdSecret: b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA==
  - in: /api/health/passheader
    out: /api/health/liveness
    accessToken:
      option: forward
  - in: /api/health/forwardtoken
    out: /api/health/jwtreceiver
    accessToken:
      option: forward
```


In the above example, the `in` defines the inbound request path, in first example of `/api/scope/callread`, and `out` defines the outbound request going out to another api `/api/scope/read`. The `accessToken` section indicates whether to use Client Credentials Flow to generate a access-token when `option` field has a value of `request`.  The `scopes` sections indicates the scopes to request from the authorization server.  The scopes can include multiple scope values such as "message.read message.write".

You can also forward the inbound access-token using the `accessToken` of `option` with `forward` value or not send it to outbound api with `doNothing` value.

The `base64EncodedClientIdSecret` is the ClientId and Client Secret values encoded using base64.  On mac use `echo -n 'oauth-client:oauth-secret' | openssl base64` to encode your username and password.


## How to use this in your Spring Maven based project
To use this `token-filter` in your maven based project include the following in your pom.xml as:
```
<dependency>
  <groupId>me.sonam</groupId>
  <artifactId>token-filter</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Or in gradle:

```
dependencies {
 implementation 'me.sonam:token-filter:1.0.0-SNAPSHOT'
}
```

Then in your class you have to enable component scan as following to pick up this  library package:

``` 
@ComponentScan(basePackages = {"me.sonam.security"})
```

or do

```
@SpringBootApplication(scanBasePackages = {"me.sonam", "include.your.app.base.code.package.also.if.needed."})
```

You also have to ensure your application is scanned too.  So you may have to add additional package to scan as well.


This `token-filter` library is meant to be deployed using a Eureka discovery service.  Therefore, this uses `loadbalanced` webclients.  The following is an example of how to configure one for example or use bean override as well.
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
    @Bean
    public WebClient.Builder webClientBuilderNoFilter() {
        LOG.info("returning another loadbalanced webclient");
        return WebClient.builder();
    }

    @Bean
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(webClientBuilderNoFilter());
    }

    //this can be your business service for example
    @Bean
    public SimpleAuthenticationService simpleAuthenticationService() {
        return new SimpleAuthenticationService(webClientBuilder());
    }
}
```
The loadbalanced webclient will be used for the business service such as `SimpleAuthenticationService` or any other business service.  The `noFilter` beans are used by the `ReactiveRequestContextHolder` service for Client Credentials Flow filter.

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
    public ReactiveRequestContextHolder reactiveRequestContextHolder() {
        return new ReactiveRequestContextHolder(webClientBuilder());
    }

    @Bean
    public SimpleAuthenticationService userAccountService() {
        return new SimpleAuthenticationService(webClientBuilder());
    }
}
```

### How to use curl to get access-token using Client Credentials Flow
`curl -X POST 'http://localhost:9000/oauth2/token?grant_type=client_credentials&scope=message.read%20message.write' \
--header 'Authorization: Basic b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA=='`


The following is the response from the authorization server:

`{"access_token":"eyJraWQiOiJmY2UzYWU2My0wZjNhLTQ1OWYtODkwOS1lN2JiOWM3M2NkODkiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvYXV0aC1jbGllbnQiLCJhdWQiOiJvYXV0aC1jbGllbnQiLCJuYmYiOjE2ODQxMTU0MzksInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjg0MTE1NzM5LCJpYXQiOjE2ODQxMTU0MzksImF1dGhvcml0aWVzIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXX0.g__CojLV9yD-KEzIHDimmAbomap3vvgfK4KiMVJn8GvPZesD1d3QLGkzNXA_J4DHZt5VbWFbh6Q0iE2gx5bWmzsMKFDiVot2w-b79rhXE22JnlhX2uvYUO_APum3TQGvy0QCIoOXug98HqoiLyveyVZVMkTcwlO2zZyajR8QdGN3B7U9C47-mlZ0ZAahb_cXHdyGaM68ibaXcEArIrwRtprcSA82EJCy3XRoz_5eKo8-qldjsmXwQ2km4otJ4QHnw7zjJ0FZytLUGxAvlJjqpULCstCkuKM7BBFQZHkzjHhjdajPWHhwzTmKTXywJW2780ckssS_9UzggZfc0RXa6w","scope":"message.read message.write","token_type":"Bearer","expires_in":299}`



Fore more on how to use this `token-filter` from github to another github repository follow [How to use maven library from github in your maven project?](https://sonamsamdupkhangsar.github.io/pulling-down-github-maven-library/)

To publish this library to local maven repo:
`./gradlew publishToMavenLocal `

### Release notes

1.0.2-SNAPSHOT

This library has been updated to use HTTP POST for calling Spring Authorization Server for requesting token using Client Credential Grant.
