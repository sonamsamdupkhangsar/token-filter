package me.sonam.security;

import lombok.extern.java.Log;
import me.sonam.security.jwt.JwtCreator;

import me.sonam.security.jwt.PublicKeyJwtCreator;
import me.sonam.security.jwt.PublicKeyJwtDecoder;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.JwtKey;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.BeforeAll;

import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Calendar;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
//@RunWith(SpringRunner.class)
@SpringBootTest(classes = {Application.class})
@ExtendWith(MockitoExtension.class)
public class JwtValidation {
    private static final Logger LOG = LoggerFactory.getLogger(JwtValidation.class);

    @Autowired
    private PublicKeyJwtCreator jwtCreator;

    @Autowired
    private PublicKeyJwtDecoder rPublicKeyJwtDecoder;

    @Autowired
    private JwtKeyRepository jwtKeyRepository;

    private static MockWebServer mockWebServer;

    private static String jwtRestServicePublicKeyId ="http://localhost:{port}/jwt-rest-service/publickeys/{keyId}";

    /**
     * this method will update the 'jwt-rest-service-public-key-id' endpoint address to the mockWebServer port
     * so that it can be mocked.
     * @param r
     * @throws IOException
     */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
        r.add("jwt-rest-service-public-key-id", () -> jwtRestServicePublicKeyId.replace("{port}",
                mockWebServer.getPort()+""));
        LOG.info("updated jwtRestServicePublicKeyId property");
    }

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
    public static void tearDown() throws Exception {
        mockWebServer.shutdown();
        LOG.info("shut down mockWebServer");
    }

    @Test
    public void createJwt() throws Exception {
        LOG.info("Create jwt");


        LOG.info("host: {}, port: {}", mockWebServer.getHostName(), mockWebServer.getPort());

        JwtKey jwtKey = jwtCreator.createJwtKey();
        jwtKeyRepository.save(jwtKey).subscribe(jwtKey1 -> LOG.info("saved jwtKey: {}", jwtKey1));
        Key publicKey = rPublicKeyJwtDecoder.loadPublicKey(jwtKey.getPublicKey());
        LOG.info("loaded publicKey object");


        mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(jwtKey.getPublicKey()));

        final String clientId = "sonam-123-322";
        final String groups = "Admin, Cameramen, Driver, foodballer";
        Mono<String> jwtTokenString = jwtCreator.create(clientId, groups, "sonam-username", "https://sonam.cloud", Calendar.HOUR, 5);

        Mono<Jwt> jwtMono = jwtTokenString.flatMap(token -> rPublicKeyJwtDecoder.decode(token));

        jwtMono.as(StepVerifier::create).assertNext(jwt -> {
            RecordedRequest request = null;
            try {
                request = mockWebServer.takeRequest();
            } catch (InterruptedException e) {
                LOG.error("exception occured on takingRequest", e);
            }
            Assertions.assertThat(request.getMethod()).isEqualTo("GET");

            LOG.info("jwt.issuedAt: {}, localDateTime: {}",jwt.getIssuedAt(), LocalDateTime.ofInstant(jwt.getIssuedAt(), ZoneOffset.UTC));
            LOG.info("jwt.expiresAt: {}, localDateTime: {}", jwt.getExpiresAt(), LocalDateTime.ofInstant(jwt.getExpiresAt(), ZoneOffset.UTC));
            LOG.info("jwt.alg: {}", jwt.getHeaders().get("alg"));
            LOG.info("jwt.audience: {}", jwt.getAudience());
            LOG.info("jwt.subject: {}", jwt.getSubject());
            LOG.info("jwt.issuer: {}", jwt.getIssuer().toString());
            LOG.info("jwt.clientId: {}", jwt.getHeaders().get("clientId"));
            LOG.info("jwt.groups: {}", jwt.getHeaders().get("groups"));
            LOG.info("jwt.keyId: {}", jwt.getHeaders().get("keyId"));
            LOG.info("jwt.headers: {}", jwt.getHeaders().toString());
            LOG.info("headsers: {}", jwt.getHeaders());

            assertThat(jwt.getIssuedAt()).isNotNull();
            assertThat(jwt.getExpiresAt()).isNotNull();
            assertThat(jwt.getHeaders().get("alg")).isNotNull();
            assertThat(jwt.getAudience()).contains("https://sonam.cloud");
            assertThat(jwt.getSubject()).isEqualTo("sonam-username");

            LOG.info("claims: {}", jwt.getClaims());

            assertThat(jwt.getHeaders().get("clientId")).isEqualTo(clientId);
            assertThat(jwt.getHeaders().get("groups")).isEqualTo(groups);
            assertThat(jwt.getHeaders().get("keyId")).isEqualTo(jwtKey.getId());

            try {
                assertThat(jwt.getIssuer()).isEqualTo(new URL("https://www.sonam.cloud"));
            } catch (MalformedURLException e) {
                LOG.error("error occured for matching issuer", e);
            }
            assertThat(jwt.getClaims()).isNotNull();}).verifyComplete();
    }
}
