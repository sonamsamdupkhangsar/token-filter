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
    private AllowProps allowProps;

    @Autowired
    private PermitPath permitPath;

    @Autowired
    private JwtPath jwtPath;

    @Test
    public void jwtPath() {
        LOG.info("jwt.path: {}", jwtPath.getJwtRequest().size());
        assertThat(jwtPath.getJwtRequest().size()).isEqualTo(2);

        assertThat(jwtPath.getJwtRequest().get(0).getIn()).isEqualTo("/api/health/passheader");
        assertThat(jwtPath.getJwtRequest().get(0).getOut()).isEqualTo("/jwts/accesstoken");

        assertThat(jwtPath.getJwtRequest().get(1).getIn()).isEqualTo("/api/health/passheader");
        assertThat(jwtPath.getJwtRequest().get(1).getOut()).isEqualTo("/api/health/jwtreceiver");

    }
    @Test
    public void yamlTest() {
        LOG.info("permitPath: {}", permitPath);
        LOG.info("allowProps: {}", allowProps);
        permitPath.getPermitpath().forEach(path -> {
            LOG.info("path: {}, method: {}", path.getPath(), path.getHttpMethods());
        });
    }
}
