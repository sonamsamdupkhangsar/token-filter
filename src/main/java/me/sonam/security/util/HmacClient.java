package me.sonam.security.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HmacClient {
    @Value("${hmacKey.clientId:}")
    private String clientId;

    @Value("${hmacKey.algorithm:}")
    private String algorithm;

    @Value("${hmacKey.secretKey:}")
    private String secretKey;

    public HmacClient() {

    }
    public HmacClient(String clientId, String algorithm, String secretKey) {
        this.clientId = clientId;
        this.algorithm = algorithm;
        this.secretKey = secretKey;
    }

    public String getClientId() {
        return clientId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSecretKey() {
        return secretKey;
    }

    @Override
    public String toString() {
        return "HmacClient{" +
                "clientId='" + clientId + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", secretKey='" + secretKey + '\'' +
                '}';
    }
}
