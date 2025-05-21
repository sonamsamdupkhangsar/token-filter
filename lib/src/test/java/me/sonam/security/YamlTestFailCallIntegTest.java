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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;


/**
 * this test is to verify passing a jwt header from called service to another.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@ActiveProfiles("inouthttp-empty-call-fail")
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class YamlTestFailCallIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(YamlTestFailCallIntegTest.class);

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


    /**
     * This test will pick up the first requestFilter matching from the yaml
     * and do nothing to pass the token.  It will fail as the jwtreceiver gets the wrong response.
     * This test is to verify it picks the first matching in, out and inHttpMethods param
     * instead of the general empty one.  A better test would do verify the method called
     * but it works for now.
     * @throws InterruptedException
     */
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

        LOG.info("call passheader endpoint /api/health/passheader");
        client.get().uri("/api/health/passheader")
                .exchange().expectStatus().is5xxServerError();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/api/health/jwtreceiver");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("GET");
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
