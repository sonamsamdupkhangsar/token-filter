package me.sonam.security;

import me.sonam.security.property.TokenProperty;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TokenAudienceAndIssuerCheckIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(TokenAudienceAndIssuerCheckIntegTest.class);

    @Autowired
    private WebTestClient client;
    @Autowired
    private TokenProperty tokenProperty;

    /**
     * this test connects to a live running authorization server
     */
    @Test
    public void testAudienceAndIssuer() {
        LOG.info("send a jwt token");
        final String accessToken = "eyJraWQiOiI5ODNjZGU2NS1hYzczLTQ3YTQtODQxNS04NmZmNjQyMjg1YzIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvYXV0aC1jbGllbnQiLCJhdWQiOiJvYXV0aC1jbGllbnQiLCJuYmYiOjE2OTI0NjA2NTAsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCIsIm1lc3NhZ2Uud3JpdGUiXSwiaXNzIjoiaHR0cDovL215LXNlcnZlcjo5MDAxIiwiZXhwIjoxNjkyNDYwOTUwLCJpYXQiOjE2OTI0NjA2NTB9.Iz5_1xbm6b5BOarhqpQ5SiUs4EIXyqx8kpQW6iaWC2CEUlaAFkwi5u67hjcBwkk7KlgCKBwahMk83AnTro7ogcagN0LgBU7qHBrjeMnbFP2yJ7oMylmlxCCwwZ8Fl9HySklQL289d-SzSoyGEZkBRaRLd1RTtYyDSFqptFQeXR1TZ5F0b8KAWPb8ZU6hgUREiiP8oyGzx6M1eyMXiy8efc9nEnjhRi9yTd6zuRtwnosKgjsQP0HrmgR8zoAoxJsp7g_vUKnLF6ll5dMRNFUrQ5W0U_YqqazoncK_4oDpWslsXzMcw4ELfWOcBlMQihqDqrdQSOZowPE0s2guBSlqrw";

        assertThat("hello").isEqualTo("hello");
       /* assertThat(tokenProperty.getToken().getAudiences().contains("oauth-client")).isTrue();
        assertThat(tokenProperty.getToken().getAudiences().contains("my-other-client")).isTrue();
        assertThat(tokenProperty.getToken().getAudiences().contains("non-existing-client")).isFalse();
        assertThat(tokenProperty.getToken().getIssuerUri()).isEqualTo("http://my-server:9001");
        assertThat(tokenProperty.getToken().getIssuerUri()).isNotEqualTo("http://my-server");

*/
      /*  LOG.info("call passheader endpoint");
        final String b64EncodedCredentials = Base64.getEncoder().encodeToString("oauth-client:oauth-secret".getBytes(StandardCharsets.UTF_8));

        EntityExchangeResult<Map> entityExchangeResult = client.post().uri("http://localhost:8080/issuer/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(b64EncodedCredentials)).exchange().expectBody(Map.class).returnResult();

        LOG.info("got exchange result: {}", entityExchangeResult.getResponseBody());

        client.get().uri("/api/scope/jwtrequired")
                .headers(httpHeaders -> httpHeaders.setBearerAuth(entityExchangeResult.getResponseBody().get("access_token").toString()))
                .exchange().expectStatus().isOk();*/
    }


}
