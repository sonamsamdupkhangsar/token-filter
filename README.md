# jwt-validator
This is a security library to validate JWT token issued by a spring-authorization-server that implements OAuth 2.1 and OpenID Connect 1.0 specifications.

## Use case
This library is used for securing access to api endpoints and also allowing access to certain health endpoints that shouldn't require access-tokens.

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
  <version>1.3-SNAPSHOT</version>
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

The following example shows the endpoints that can be allowed to such as the
`/api/health/readiness` endpoint which don't require any access-tokens.  In this endpoint, both `GET` and `POST` methods are allowed without a token.  
For `/api/scope/read` endpoint a access-token is required that must have a scope of either
`message.read` or `message.write`.

```
permitpath:
  - path: /api/health/readiness
    httpMethods: GET, POST
  - path: /api/scope/callread
    httpMethods: GET
  - path: /api/scope/read
    scopes: message.read, message.write    
```

This jwt-validator library can also request access-token to be created from the spring authorization server using `Client Credentials Flow` token.  This can be done
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
In the above example, the `in` defines the inbound request path of `/api/scope/callread` and `out` defines the outbound request going out to another api `/api/scope/read`. The `accessToken` section indicates whether to use Client Credentials Flow to generate a access-token when `option` field has a value of `request`.  The `scopes` sections indicates the scopes to request from the authorization server.  The scopes can include multiple scope values such as "message.read message.write".
The `base64EncodedClientIdSecret` is the ClientId and Client Secret values encoded using base64.

You can also forward the inbound access-token using the `accessToken` of `option` with `forward` value or not send it to outbound api with `doNothing` value.

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
    @Bean
    public WebClient.Builder webClientBuilderNoFilter() {
        LOG.info("returning another loadbalanced webclient");
        return WebClient.builder();
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

curl -X POST 'http://localhost:9000/oauth2/token?grant_type=client_credentials' \  
--header 'Authorization: Basic b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA=='
{"access_token":"eyJraWQiOiIxZDA2NmM0NS1hMDVmLTRhMjUtOWYwYS1hM2NiZTgxZmNmYWYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvYXV0aC1jbGllbnQiLCJhdWQiOiJvYXV0aC1jbGllbnQiLCJuYmYiOjE2ODM3NzEwOTAsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY4Mzc3MTM5MCwiaWF0IjoxNjgzNzcxMDkwfQ.d0pIwbTTF3NdMQ0x_ateveA551OuiLce7O0jKAzbmPpjTvXxq82RJVIHOdqW_MrRIW-yApt1HUE85wbPRS7C7KXYjuNeY73uva5KYNGGmGL__wokUvOQerohDv6PbLYupoIK3lx63OUYz3atSimXZ48tSHzdnNtMAh9Kw7sRE86UZLjzXk80WIQ5UNVY7_r6mwLrNiz_jjxEP2hW7HOCbR42bi3GL9u9veYR2p9nggDTwom8dN0zeIxGuWRbPPv4v8WPUlg8egUAEJadAiXC7LzEn_apvH_zkAx-ZRhqic4I_EdoWv7MUjyl0B4n2olvMeQwhM9S2OmnZDdrlNf8NQ","token_type":"Bearer","expires_in":299}%


Fore more on how to use this `jwt-validator` from github to another github repository follow [How to use maven library from github in your maven project?](https://sonamsamdupkhangsar.github.io/pulling-down-github-maven-library/)

