package me.sonam.security;


import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
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
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;


/**
 * This test is to call multiple endpoints from the main rest-service endpoint.
 * This will test the request option which will request a new token if no inbound token found and
 * then use that token for subsequent calls within that same webservice to other rest-services.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@ActiveProfiles("request-token")
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class CallMultiEndpointRequestOptionIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(CallMultiEndpointRequestOptionIntegTest.class);

    @Autowired
    private WebTestClient client;

    @MockitoBean
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

    @MockitoSpyBean
    private EndpointHandler endpointHandler;

    @MockitoSpyBean
    private ReactiveRequestContextHolder reactiveRequestContextHolder;

    private static String jwtReceiverEndpoint = "http://localhost:{port}";///api/health/jwtreceiver";
    private static String apiPassHeaderEndpoint = "http://localhost:{port}/api/health/passheader";
    private static String jwtRestServiceAccesstoken = "http://localhost:{port}";
    final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

    final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";

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
    public void hello() {
        LOG.info("do nothing");
    }
    public void callMultiEndpoints() throws InterruptedException {
        LOG.debug("this will call api/multi-call endpoint which will call multiple endpoints to test" +
                "that the access-token is reused 3 times");
        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                        .setResponseCode(200).setBody(jwtTokenMsg));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{ \"message\": \"logged-in user: "+authenticationId+"\"}"));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/multi-call")
                .exchange().expectStatus().isOk();

        LOG.info("Verify each of the jwtrequest endpoints are called");

        verify(endpointHandler, times(1)).callGetEndpoint("/api/scope/jwtrequired");
        verify(endpointHandler, times(1)).callGetEndpoint("/api/scope/jwtrequired2");
        verify(endpointHandler, times(1)).callGetEndpoint("/api/scope/jwtrequired3");
        verify(endpointHandler, times(1)).callGetEndpoint("/api/scope/jwtrequired4");

        LOG.debug("Verify that the generateAccessToken is only called once.");
        verify(reactiveRequestContextHolder, times(1)).generateAccessToken(any());

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("token request: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/issuer/oauth2/token");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");
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
