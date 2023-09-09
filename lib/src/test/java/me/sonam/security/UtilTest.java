package me.sonam.security;

import me.sonam.security.util.Util;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class UtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(UtilTest.class);

    @Test
    public void hmacCreate() {
        final String mac = Util.getHmac("HmacMD5", "hello", "secretkey");
        AssertionsForClassTypes.assertThat(mac).isNotNull();
        LOG.info("hmac: {}", mac);

    }
}
