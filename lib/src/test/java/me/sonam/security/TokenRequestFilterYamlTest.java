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
        assertThat(tokenRequestFilter.getRequestFilters().size()).isEqualTo(15);

        int index = 5;
        
        LOG.info("jwtPath[0].toString: {}", tokenRequestFilter.getRequestFilters().get(index).toString());
        LOG.info("jwtPath[0].toString: {}", tokenRequestFilter.getRequestFilters().get(index).toString());
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/passheader");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(1);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("delete")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");

        index++;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/passheader");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(3);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("get")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("post")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("put")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("delete")).isFalse();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("request");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("doNothing");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isEqualTo("message.read message.write");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNotEqualTo("message.read");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isEqualTo("b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA==");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNotEqualTo("randomstring");

        index++;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/passheader");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/liveness");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(3);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("get")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("post")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("head")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("put")).isFalse();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("request");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNull();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNull();

        index++;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/health/forwardtoken");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(2);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("get")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("delete")).isTrue();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("put")).isFalse();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().contains("post")).isFalse();

        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNull();
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNull();

        index++;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/scope/callread");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/scope/read");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(3);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("request");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("doNothing");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isEqualTo("message.read");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getScopes()).isNotEqualTo("message.read message.write");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isEqualTo("b2F1dGgtY2xpZW50Om9hdXRoLXNlY3JldA==");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getBase64EncodedClientIdSecret()).isNotEqualTo("randomstring");

        index++;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/api/scope/dummyin");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/api/scope/dummyout");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(0);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isNotEqualTo("doNothing");

        index++;
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getIn()).isEqualTo("/.*");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getOut()).isEqualTo("/accounts/email/.*");
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getInHttpMethodSet().size()).isEqualTo(1);
        assertThat(tokenRequestFilter.getRequestFilters().get(index).getAccessToken().getOption().name()).isEqualTo("forward");



        LOG.info("path: {}", tokenRequestFilter.getRequestFilters().get(index).getIn());
        String inPath = "/users";

        boolean inMatch = tokenRequestFilter.getRequestFilters().get(index).getInSet().stream().anyMatch(w -> {
            LOG.info("w {} inMatch path {}", w, inPath);
            return inPath.matches(w);});

        if (inMatch) {
            LOG.info("inMatch found");
        }
        else {
            LOG.info("inMatch not found");
        }

        assertThat(inMatch).isTrue();

        inMatch = tokenRequestFilter.getRequestFilters().get(index).getOutSet().stream().anyMatch(w -> {
            LOG.info("w {} outMatch path {}", w, inPath);
            return inPath.matches(w);});

        if (inMatch) {
            LOG.info("inMatch found");
        }
        else {
            LOG.info("inMatch not found");
        }

        assertThat(inMatch).isFalse();


        String emailPath = "/accounts/email/apple@some.com";
        boolean outMatch = tokenRequestFilter.getRequestFilters().get(index).getOutSet().stream().anyMatch(w -> {
            LOG.info("w {} outMatch path {}", w, emailPath);
            return emailPath.matches(w);});
        if (outMatch) {
            LOG.info("outMatch found");
        }
        else {
            LOG.info("outMatch not found");
        }

        assertThat(outMatch).isTrue();

    }
    @Test
    public void yamlTest() {
        LOG.info("permitPath: {}", permitPath);
        permitPath.getPermitpath().forEach(path -> {
            LOG.info("path: {}, method: {}", path.getPath(), path.getHttpMethods());
        });
    }

    @Test
    public void urlEncodedEmailPath() {
        final String path = "/accounts/email/sendAuthenticationId%2540sonam.co/authentication-id";

        final String exp = "/accounts/(.)*/(.)*";
        boolean matchOutPath = path.matches(exp);

        LOG.info("matchOutput is {}, path {}, exp {}", matchOutPath, path, exp);
        assertThat(matchOutPath).isTrue();
    }
}
