package me.sonam.security;


import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.Before;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;


/**
 * this test is to verify passing a jwt header from called service to another.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ExtendWith(MockitoExtension.class)
public class JwtHeaderPassIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(JwtHeaderPassIntegTest.class);

    @Autowired
    private WebTestClient client;

    @MockBean
    ReactiveJwtDecoder jwtDecoder;
    private static MockWebServer mockWebServer;

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

        //r.add("jwt-receiver.root", () -> jwtReceiverEndpoint.replace("{port}", serverProperties.getPort()+""));

        LOG.info("mockWebServer.port: {}", mockWebServer.getPort());
    }
    @Test
    public void noPassHeaderJwt() {
        LOG.info("readiness delete requires jwt, should get bad request");

        client.get().uri("/api/health/jwtreceiver")
                .exchange().expectStatus().isOk();
    }

    @Test
    public void demoClientErrorRetrieve() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/callthrowerror")
                .exchange().expectStatus().is5xxServerError();

    }


    @Test
    public void passHeaderJwt() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

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
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
    }

    @Test
    public void callWithJwtToken() throws InterruptedException {
        LOG.info("readiness delete requires jwt, should get bad request");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

        final String jwtTokenMsg = " {\"token\":\""+jwtString+"\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jwtTokenMsg));

        final String jwtReceiver = " {\"message\":\"jwt received endpoint\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(200).setBody(jwtReceiver));//"Account created successfully.  Check email for activating account"));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/passheader")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
    }

    @Test
    public void callJwtReceiver() throws InterruptedException {
        LOG.info("this will call `calljwtreceiver` endpoint which will call jwtreceiver endpoint");
        LOG.info("this will test to ensure service can call another endpoint");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/calljwtreceiver")//.headers(addJwt(jwt))
                .exchange().expectStatus().isOk();
    }

    @Test
    public void forwardtoken() throws InterruptedException {
        LOG.info("this will call `calljwtreceiver` endpoint which will call jwtreceiver endpoint");
        LOG.info("this will test to ensure service can call another endpoint");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/forwardtoken")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk();
    }


    private Jwt jwt(String subjectName) {
        return new Jwt("token", null, null,
                Map.of("alg", "none"), Map.of("sub", subjectName));
    }

    private Consumer<HttpHeaders> addJwt(Jwt jwt) {
        return headers -> headers.setBearerAuth(jwt.getTokenValue());
    }

}
