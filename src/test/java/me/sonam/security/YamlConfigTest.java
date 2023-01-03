package me.sonam.security;

import lombok.extern.java.Log;
import me.sonam.security.property.PermitPath;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

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

    @Test
    public void yamlTest() {
        LOG.info("permitPath: {}", permitPath);
        LOG.info("allowProps: {}", allowProps);
        permitPath.getPermitpath().forEach(path -> {
            LOG.info("path: {}, method: {}", path.getPath(), path.getHttpMethods());
        });
    }
}
