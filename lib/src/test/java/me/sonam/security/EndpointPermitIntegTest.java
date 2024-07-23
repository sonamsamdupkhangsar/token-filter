package me.sonam.security;

import io.jsonwebtoken.Jwts;
import lombok.extern.java.Log;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;

/**
 * Test the liveness and readiness endpoints
 */
@AutoConfigureWebTestClient
@Log
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {Application.class})
public class EndpointPermitIntegTest {
  private static final Logger LOG = LoggerFactory.getLogger(EndpointPermitIntegTest.class);

  @Autowired
  private WebTestClient client;

  @MockBean
  ReactiveJwtDecoder jwtDecoder;

  @Test
  public void scopeReadCheck() {
    LOG.info("api/scope/read check");
    final String authenticationId = "dave";
    Jwt jwt = jwt(authenticationId);

    LOG.info("the following is needed to return the correct jwt");
    Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

    final String jwtString = createJwt("sonam", "message.read");
    client.get().uri("/api/scope/read")
           .headers(addJwt(jwtString)) //this is not the actual one
            .exchange().expectStatus().isOk();
  }

  @Test
  public void apiCallFailScope() {
    LOG.info("ap/scope/read check fail test");
    final String authenticationId = "dave";
    Jwt jwt = jwt(authenticationId, "message:none");

    Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

    final String jwtString = createJwt("sonam", "message:none");
    client.get().uri("/api/scope/read")
            .headers(addJwt(jwtString))
            .exchange().expectStatus().isUnauthorized();
  }


  @Test
  public void readinessEndpointPermittedPublic() {
    LOG.info("readiness get is permitted without jwt");
    client.get().uri("/api/health/readiness")
            .exchange().expectStatus().isOk();
  }

  @Test
  public void readinessPostAllowed() {
    LOG.info("readiness post is permitted without jwt");

    client.post().uri("/api/health/readiness")
            .exchange().expectStatus().isOk();
  }

  @Test
  public void readinessDeleteRequiresJwt() {
    LOG.info("readiness delete requires jwt, should get bad request");

    client.delete().uri("/api/health/readiness")
            .exchange().expectStatus().isUnauthorized();
  }

  @Test
  public void livenessEndpoindRequiresJwtWithJwt() {
    LOG.info("this endpoint requires jwt endpoint");
    final String authenticationId = "dave";
    Jwt jwt = jwt(authenticationId);
    Mockito.when(this.jwtDecoder.decode(ArgumentMatchers.anyString())).thenReturn(Mono.just(jwt));

    client.get().uri("/api/health/liveness")
            .headers(addJwt(jwt))
            .exchange().expectStatus().isOk();
  }

  @Test
  public void livenessEndpoindRequiresJwtWithoutJwt() {
    LOG.info("this endpoint requires jwt endpoint but will fail with 404 error when jwt is not sent");

    client.get().uri("/api/health/liveness")
            .exchange().expectStatus().is4xxClientError();
  }

  @Test
  public void livenessEndpoindHeadAllowed() {
    LOG.info("liveness Head allowed");

    client.head().uri("/api/health/liveness")
            .exchange().expectStatus().isOk();
  }

  @Test
  public void livenessEndpoindPostAllowed() {
    LOG.info("liveness post allowed");

    client.post().uri("/api/health/liveness")
            .exchange().expectStatus().isOk();
  }


  private Jwt jwt(String subjectName) {
    return new Jwt("thisismytoken", null, null,
            Map.of("alg", "none"), Map.of("sub", subjectName, "scope", "message.read"));
  }
  private Jwt jwt(String subjectName, String scope) {
    return new Jwt("thisismytoken", null, null,
            Map.of("alg", "none"), Map.of("sub", subjectName, "scope", scope));
  }

  private Consumer<HttpHeaders> addJwt(Jwt jwt) {

    LOG.info("add tokenValue: {}", jwt.getTokenValue());
    return headers -> headers.setBearerAuth(jwt.getTokenValue());
  }

  private Consumer<HttpHeaders> addJwt(final String jwt) {

    LOG.info("add jwt: {}", jwt);
    return headers -> headers.setBearerAuth(jwt);
  }
  private String createJwt(final String subject, final String... scopes) {

    Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
    Date issueDate = calendar.getTime();

    Duration duration = Duration.ofSeconds(60);

    calendar.add(Calendar.SECOND, (int)duration.getSeconds());

    Date expireDate = calendar.getTime();

    LOG.debug("load private key");

    LOG.debug("add claims to jwt");
    Map<String, Object> claimsMap = new HashMap<>();
    claimsMap.put("clientId", "123-client-id");
    claimsMap.put("scope", List.of(scopes));
    claimsMap.put("role", List.of("admin", "manager", "user"));

    String jwt = Jwts.builder()
            .setSubject(subject)
            .setIssuer("http://localhost:9000")
            .setAudience("http://localhost:9000")
            .setIssuedAt(issueDate)
            .addClaims(claimsMap)
            .setExpiration(expireDate)
            .setId(UUID.randomUUID().toString())
            .compact();
    return jwt;
  }
}
