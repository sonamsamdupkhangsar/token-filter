package me.sonam.security;

import lombok.extern.java.Log;
import me.sonam.security.property.PermitPath;
import me.sonam.security.util.TokenRequestFilter;

import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@AutoConfigureWebTestClient
@Log
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {Application.class})
public class TokenRequestFilterYamlTest {
    private static final Logger LOG = LoggerFactory.getLogger(TokenRequestFilterYamlTest.class);

    @Autowired
    private PermitPath permitPath;

    @Autowired
    private TokenRequestFilter tokenRequestFilter;

    @Test
    public void jwtPath() {
        LOG.info("jwt.path: {}", tokenRequestFilter.getRequestFilters().size());
        assertThat(tokenRequestFilter.getRequestFilters().size()).isEqualTo(6);

        int index = 0;
        
        LOG.info("jwtPath[0].toString: {}", tokenRequestFilter.getRequestFilters().get(index).toString());
        LOG.info("jwtPath[0].toString: {}", tokenRequestFilter.getRequestFilters().get(index).toString());
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/passheader");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().size()).isEqualTo(1);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("delete")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");

        index = 1;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/passheader");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().size()).isEqualTo(3);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("get")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("post")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("put")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("delete")).isFalse();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("request");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("doNothing");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isEqualTo("message.read message.write");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNotEqualTo("message.read");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isEqualTo("b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA==");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNotEqualTo("randomstring");

        index = 2;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/passheader");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/liveness");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().size()).isEqualTo(3);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("get")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("post")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("head")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("put")).isFalse();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("request");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNull();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNull();

        index = 3;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/forwardtoken");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().size()).isEqualTo(2);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("get")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("delete")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("put")).isFalse();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().contains("post")).isFalse();

        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNull();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNull();

        index = 4;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/scope/callread");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/scope/read");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().size()).isEqualTo(3);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("request");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("doNothing");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isEqualTo("message.read");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNotEqualTo("message.read message.write");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isEqualTo("b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA==");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNotEqualTo("randomstring");

        index = 5;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/scope/dummyin");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/scope/dummyout");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getHttpMethodSet().size()).isEqualTo(0);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("doNothing");

    }
    @Test
    public void yamlTest() {
        LOG.info("permitPath: {}", permitPath);
        permitPath.getPermitpath().forEach(path -> {
            LOG.info("path: {}, method: {}", path.getPath(), path.getHttpMethods());
        });
    }
}
