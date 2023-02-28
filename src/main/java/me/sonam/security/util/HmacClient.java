package me.sonam.security.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HmacClient {
    @Value("${hmackey.clientId:}")
    private String clientId;

    @Value("${hmackey.hmacMD5Algorithm:}")
    private String md5Algoirthm;

    @Value("${hmackey.secretkey:}")
    private String secretKey;

    public HmacClient() {

    }
    public HmacClient(String clientId, String md5Algoirthm, String secretKey) {
        this.clientId = clientId;
        this.md5Algoirthm = md5Algoirthm;
        this.secretKey = secretKey;
    }

    public String getClientId() {
        return clientId;
    }

    public String getMd5Algoirthm() {
        return md5Algoirthm;
    }

    public String getSecretKey() {
        return secretKey;
    }
}
