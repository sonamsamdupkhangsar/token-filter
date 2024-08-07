package me.sonam.security;


import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.Before;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;


/**
 * this test is to verify passing a jwt header from called service to another.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class JwtHeaderPassIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(JwtHeaderPassIntegTest.class);

    @Autowired
    private WebTestClient client;

    @MockBean
    ReactiveJwtDecoder jwtDecoder;
    private static MockWebServer mockWebServer;

    @Autowired
    ApplicationContext context;

    @org.junit.jupiter.api.BeforeEach
    public void setup() {
        this.client = WebTestClient
                .bindToApplicationContext(this.context)
                // add Spring Security test Support
                .apply(springSecurity())
                .configureClient()
                //   .filter(basicAuthentication("user", "password"))
                .build();
    }

    private static String jwtReceiverEndpoint = "http://localhost:{port}";///api/health/jwtreceiver";
    private static String apiPassHeaderEndpoint = "http://localhost:{port}/api/health/passheader";
    private static String jwtRestServiceAccesstoken = "http://localhost:{port}";
    @Autowired
    private ServerProperties serverProperties;


    @Before
    public void setUp() {
        LOG.info("setup mock");
        MockitoAnnotations.openMocks(this);
    }

    @BeforeAll
    static void setupMockWebServer() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        LOG.info("host: {}, port: {}", mockWebServer.getHostName(), mockWebServer.getPort());
    }

    @AfterAll
    public static void shutdownMockWebServer() throws IOException {
        LOG.info("shutdown and close mockWebServer");
        mockWebServer.shutdown();
        mockWebServer.close();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
       // r.add("api-health-passheader", () -> apiPassHeaderEndpoint.replace("{port}", mockWebServer.getPort() + ""));
        r.add("auth-server.root", () -> "http://localhost:"+ mockWebServer.getPort());

        r.add("jwt-receiver.root", () -> jwtReceiverEndpoint.replace("{port}", mockWebServer.getPort()+""));

        LOG.info("mockWebServer.port: {}", mockWebServer.getPort());
    }
    @Test
    public void jwtRequired() {
        LOG.info("jwtrequired requires jwt, should get unauthorized response");

        client.get().uri("/api/health/jwtrequired")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    public void demoClientErrorRetrieve() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(400).setBody("bad request"));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/callthrowerror")
                .exchange().expectStatus().is5xxServerError();
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());


    }


    @Test
    public void passHeaderJwt() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

        final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jwtTokenMsg));

        final String jwtReceiver = " {\"message\":\"jwt received endpoint\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtReceiver));//"Account created successfully.  Check email for activating account"));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/passheader")
                .exchange().expectStatus().isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

        recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/api/health/jwtreceiver");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("GET");
    }


    @Test
    public void callMultipleEndpoints() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        final String jwtString= "eyJraWQiOiJlOGQ3MjIzMC1iMDgwLTRhZjEtODFkOC0zMzE3NmNhMTM5ODIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJhdWQiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJuYmYiOjE3MTQ3NTY2ODIsImlzcyI6Imh0dHA6Ly9teS1zZXJ2ZXI6OTAwMSIsImV4cCI6MTcxNDc1Njk4MiwiaWF0IjoxNzE0NzU2NjgyLCJqdGkiOiI0NDBlZDY0My00MzdkLTRjOTMtYTZkMi1jNzYxNjFlNDRlZjUifQ.fjqgoczZbbmcnvYpVN4yakpbplp7EkDyxslvar5nXBFa6mgIFcZa29fwIKfcie3oUMQ8MDWxayak5PZ_QIuHwTvKSWHs0WL91ljf-GT1sPi1b4gDKf0rJOwi0ClcoTCRIx9-WGR6t2BBR1Rk6RGF2MW7xKw8M-RMac2A2mPEPJqoh4Pky1KgxhZpEXixegpAdQIvBgc0KBZeQme-ZzTYugB8EPUmGpMlfd-zX_vcR1ijxi8e-LRRJMqmGkc9GXfrH7MOKNQ_nu6pc6Gish2v_iuUEcpPHXrfqzGb9IHCLvfuLSaTDcYKYjQaEUAp-1uDW8-5posjiUV2eBiU48ajYg";

        LOG.info("call passheader endpoint");
        client.mutateWith(mockJwt().jwt(jwt)).get().uri("/api/scope/callJwtRequired")
                .headers(httpHeaders -> httpHeaders.setBearerAuth(jwtString))
                .exchange().expectStatus().isOk();

    }

    /**
     * this tests the regular expression in the requestFilters for
     *   - in: /users
     *     out: /accounts/email/.*
     *     httpMethods: delete, post
     *     accessToken:
     *       option: forward
     * @throws InterruptedException
     */
   // @Test
    public void callEmailEndpoint() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        final String jwtString= "eyJraWQiOiJlOGQ3MjIzMC1iMDgwLTRhZjEtODFkOC0zMzE3NmNhMTM5ODIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJhdWQiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJuYmYiOjE3MTQ3NTY2ODIsImlzcyI6Imh0dHA6Ly9teS1zZXJ2ZXI6OTAwMSIsImV4cCI6MTcxNDc1Njk4MiwiaWF0IjoxNzE0NzU2NjgyLCJqdGkiOiI0NDBlZDY0My00MzdkLTRjOTMtYTZkMi1jNzYxNjFlNDRlZjUifQ.fjqgoczZbbmcnvYpVN4yakpbplp7EkDyxslvar5nXBFa6mgIFcZa29fwIKfcie3oUMQ8MDWxayak5PZ_QIuHwTvKSWHs0WL91ljf-GT1sPi1b4gDKf0rJOwi0ClcoTCRIx9-WGR6t2BBR1Rk6RGF2MW7xKw8M-RMac2A2mPEPJqoh4Pky1KgxhZpEXixegpAdQIvBgc0KBZeQme-ZzTYugB8EPUmGpMlfd-zX_vcR1ijxi8e-LRRJMqmGkc9GXfrH7MOKNQ_nu6pc6Gish2v_iuUEcpPHXrfqzGb9IHCLvfuLSaTDcYKYjQaEUAp-1uDW8-5posjiUV2eBiU48ajYg";

        LOG.info("call passheader endpoint");
        final String email = "sonam@yamoo.com";

        client.mutateWith(mockJwt().jwt(jwt)).put().uri("/api/scope/callEmailEndpoint/"+ URLEncoder.encode(email, Charset.defaultCharset()))
                .headers(httpHeaders -> httpHeaders.setBearerAuth(jwtString))
                .exchange().expectStatus().isOk();

    }


    /**
     * this method tests http delete method overridden for calling '/api/health/passheader -> '/api/health/jwtreceiver'
     * @throws InterruptedException
     */

    @Test
    public void passExistingHeaderJwtForDelete() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        UUID userId = UUID.randomUUID();
        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId, userId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        final String jwtString= "eyJraWQiOiJlOGQ3MjIzMC1iMDgwLTRhZjEtODFkOC0zMzE3NmNhMTM5ODIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJhdWQiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJuYmYiOjE3MTQ3NTY2ODIsImlzcyI6Imh0dHA6Ly9teS1zZXJ2ZXI6OTAwMSIsImV4cCI6MTcxNDc1Njk4MiwiaWF0IjoxNzE0NzU2NjgyLCJqdGkiOiI0NDBlZDY0My00MzdkLTRjOTMtYTZkMi1jNzYxNjFlNDRlZjUifQ.fjqgoczZbbmcnvYpVN4yakpbplp7EkDyxslvar5nXBFa6mgIFcZa29fwIKfcie3oUMQ8MDWxayak5PZ_QIuHwTvKSWHs0WL91ljf-GT1sPi1b4gDKf0rJOwi0ClcoTCRIx9-WGR6t2BBR1Rk6RGF2MW7xKw8M-RMac2A2mPEPJqoh4Pky1KgxhZpEXixegpAdQIvBgc0KBZeQme-ZzTYugB8EPUmGpMlfd-zX_vcR1ijxi8e-LRRJMqmGkc9GXfrH7MOKNQ_nu6pc6Gish2v_iuUEcpPHXrfqzGb9IHCLvfuLSaTDcYKYjQaEUAp-1uDW8-5posjiUV2eBiU48ajYg";

        final String jwtReceiver = " {\"message\":\"jwt received endpoint\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtReceiver));//"Account created successfully.  Check email for activating account"));

        LOG.info("call passheader endpoint");
        client.mutateWith(mockJwt().jwt(jwt)).delete().uri("/api/health/passheader")
                .headers(httpHeaders -> httpHeaders.setBearerAuth(jwtString))
                .exchange().expectStatus().isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();

        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/api/health/jwtreceiver");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("GET");
    }


    @Test
    public void callWithJwtToken() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

        final String jwtTokenMsg = " {\"token\":\""+jwtString+"\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jwtTokenMsg));

        final String jwtReceiver = " {\"message\":\"jwt received endpoint\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtReceiver));//"Account created successfully.  Check email for activating account"));

        LOG.info("call passheader endpoint \"/api/health/passheader\"");
        client.get().uri("/api/health/passheader")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

        recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/api/health/jwtreceiver");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("GET");
    }

    @Test
    public void callJwtReceiver() throws InterruptedException {
        LOG.info("this will call `calljwtreceiver` endpoint which will call jwtreceiver endpoint");
        LOG.info("this will test to ensure service can call another endpoint");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{ \"message\": \"logged-in user: "+authenticationId+"\"}"));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/calljwtreceiver")//.headers(addJwt(jwt))
                .exchange().expectStatus().isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
    }

    @Test
    public void forwardtoken() throws InterruptedException {
        LOG.info("this will call `calljwtreceiver` endpoint which will call jwtreceiver endpoint");
        LOG.info("this will test to ensure service can call another endpoint");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{ \"message\": \"logged-in user: "+authenticationId+"\"}"));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/forwardtoken")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
    }


    private Jwt jwt(String subjectName) {
        return new Jwt("token", null, null,
                Map.of("alg", "none"), Map.of("sub", subjectName));
    }

    private Jwt jwt(String subjectName, UUID userId) {
        return new Jwt("token", null, null,
                Map.of("alg", "none"), Map.of("sub", subjectName, "userId", userId.toString()));
    }

    private Consumer<HttpHeaders> addJwt(Jwt jwt) {
        return headers -> headers.setBearerAuth(jwt.getTokenValue());
    }

}
