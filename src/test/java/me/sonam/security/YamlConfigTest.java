package me.sonam.security;

import lombok.extern.java.Log;
import me.sonam.security.property.PermitPath;
import me.sonam.security.util.JwtPath;
import org.junit.Test;
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
public class YamlConfigTest {
    private static final Logger LOG = LoggerFactory.getLogger(YamlConfigTest.class);

    @Autowired
    private PermitPath permitPath;

    @Autowired
    private JwtPath jwtPath;

    @Test
    public void jwtPath() {
        LOG.info("jwt.path: {}", jwtPath.getJwtRequest().size());
        assertThat(jwtPath.getJwtRequest().size()).isEqualTo(3);

        LOG.info("jwtPath[0].toString: {}", jwtPath.getJwtRequest().get(0).toString());
        assertThat(jwtPath.getJwtRequest().get(0).getIn()).isEqualTo("/api/health/passheader");
        assertThat(jwtPath.getJwtRequest().get(0).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(jwtPath.getJwtRequest().get(0).getJwt()).isEqualTo("request");

        assertThat(jwtPath.getJwtRequest().get(1).getIn()).isEqualTo("/api/health/passheader");
        assertThat(jwtPath.getJwtRequest().get(1).getOut()).isEqualTo("/api/health/liveness");
        assertThat(jwtPath.getJwtRequest().get(1).getJwt()).isEqualTo("forward");

        assertThat(jwtPath.getJwtRequest().get(2).getIn()).isEqualTo("/api/health/forwardtoken");
        assertThat(jwtPath.getJwtRequest().get(2).getOut()).isEqualTo("/api/health/jwtreceiver");
        assertThat(jwtPath.getJwtRequest().get(2).getJwt()).isEqualTo("forward");
    }
    @Test
    public void yamlTest() {
        LOG.info("permitPath: {}", permitPath);
        permitPath.getPermitpath().forEach(path -> {
            LOG.info("path: {}, method: {}", path.getPath(), path.getHttpMethods());
        });
    }
}
