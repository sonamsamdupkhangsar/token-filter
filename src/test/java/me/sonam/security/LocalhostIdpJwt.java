package me.sonam.security;

import lombok.extern.java.Log;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * this is not meant to be run as a test case.  This is for connecting to a remote authorization server
 * to verify scoping function using the client credential flow.
 * To run it uncomment the annotations and  apply test to see {@link #scopeReadCheck()} method
 */
/*@AutoConfigureWebTestClient
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@Log
@RunWith(SpringRunner.class)*/
public class LocalhostIdpJwt {
    private static final Logger LOG = LoggerFactory.getLogger(LocalhostIdpJwt.class);

    @Autowired
    private ServerProperties serverProperties;

    @Autowired
    private WebTestClient webTestClient;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
        // r.add("api-health-passheader", () -> apiPassHeaderEndpoint.replace("{port}", mockWebServer.getPort() + ""));
        r.add("auth-server.root", () -> "http://localhost:9000");
    }

    @Test
    public void hello() {
        LOG.info("hello");
    }

    // @Test
    public void scopeReadCheck() {

        LOG.info("api/scope/callread check");
        LOG.info("server.port: {}", serverProperties.getPort());

        webTestClient.get().uri("/api/scope/callread")
                .exchange().expectStatus().isOk();
    }
}
