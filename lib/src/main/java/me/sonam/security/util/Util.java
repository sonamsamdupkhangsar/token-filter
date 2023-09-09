package me.sonam.security.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

public class Util {
    private static final Logger LOG = LoggerFactory.getLogger(Util.class);

    public static String getHmac(String algorithm, String data, String key) {
        LOG.info("generating hmac");

        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes()));
        }
        catch (Exception e) {
            LOG.error("Exception occured in generating hmac", e);
            return null;
        }
    }

}
