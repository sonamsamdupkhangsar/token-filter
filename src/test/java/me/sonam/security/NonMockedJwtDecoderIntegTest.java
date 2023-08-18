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
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;


/**
 * this test is to verify passing a jwt header from called service to another.
 * In the test case this mock with `jwt` is actually the one that is used
 *         `when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));`
 * For example, the username in this jwt is returned in the spring security principal
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ExtendWith(MockitoExtension.class)
public class NonMockedJwtDecoderIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(NonMockedJwtDecoderIntegTest.class);

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
    public void forwardtoken() throws InterruptedException {
        LOG.info("this will call `calljwtreceiver` endpoint which will call jwtreceiver endpoint");
        LOG.info("this will test to ensure service can call another endpoint");

        final String authenticationId = "dave";
        Jwt jwt = jwt(authenticationId);

        //this is the jwt that is actually used for user principal
        when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

        LOG.info("call passheader endpoint");
        client.get().uri("/api/health/forwardtoken")
                .headers(addJwt(jwt))
                .exchange().expectStatus().isOk().expectBody(String.class).
        consumeWith(stringEntityExchangeResult -> LOG.info("response: {}", stringEntityExchangeResult.getResponseBody()));
    }


    private Jwt jwt(String subjectName) {
        return new Jwt("1eyJraWQiOiJhNzZhN2I0My00YTAzLTQ2MzAtYjVlMi0wMTUzMGRlYzk0MGUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcml2YXRlLWNsaWVudCIsImF1ZCI6InByaXZhdGUtY2xpZW50IiwibmJmIjoxNjg3MzY5NDM5LCJzY29wZSI6WyJtZXNzYWdlLnJlYWQiLCJtZXNzYWdlLndyaXRlIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMSIsImV4cCI6MTY4NzM2OTczOSwiaWF0IjoxNjg3MzY5NDM5LCJhdXRob3JpdGllcyI6WyJtZXNzYWdlLnJlYWQiLCJtZXNzYWdlLndyaXRlIl19.chibxXXoYok5YuiTpPqD6yu8k39009oxlv4NrMggfp4wkopLP1RrWnFQ1reeTFhSFXBmNFEHMjJxOkYoj7g3B7UbgtwwjpU40VwzWDSSdJqAJxfkequtJl5D8G43wh3IPG4DpiA-uIUauicbgJmLn9WIF61_rzQCUevD-HzmB3Gv9ESa3tF2YyAve4Vp1bpFZDqwT4ntDzIkwlAMxWgJjREYjgxUA1JCnpgbvk9JFxqa4GSZtXcHfUl40-Rv_uJo1_50EimS306TnOC5pHj5_XxND-rvr4Ay5ewROVDnOwZsFu0JRaPKbiok484hDgTg7wJujzEDr7CyLfNNW7o0Og", null, null,
                Map.of("alg", "none"), Map.of("sub", subjectName));
    }

    private Consumer<HttpHeaders> addJwt(Jwt jwt) {
        return headers -> headers.setBearerAuth(jwt.getTokenValue());
    }

}
