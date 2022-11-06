package me.sonam.security;

import lombok.extern.java.Log;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

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
  public void readinessEndpointPermittedPublic() {
    LOG.info("this endpoint is permitted without jwt");
    client.get().uri("/api/health/readiness")
            .exchange().expectStatus().isOk();
  }

  @Test
  public void livenessEndpoindRequiresJwtWithJwt() {
    LOG.info("this endpoint requires jwt endpoint");
    final String authenticationId = "dave";
    Jwt jwt = jwt(authenticationId);
    when(this.jwtDecoder.decode(anyString())).thenReturn(Mono.just(jwt));

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

  private Jwt jwt(String subjectName) {
    return new Jwt("token", null, null,
            Map.of("alg", "none"), Map.of("sub", subjectName));
  }

  private Consumer<HttpHeaders> addJwt(Jwt jwt) {
    return headers -> headers.setBearerAuth(jwt.getTokenValue());
  }
}
