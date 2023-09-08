package me.sonam.security.property;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@ConfigurationProperties
public class TokenProperty {
    private Token token = new Token();

    public Token getToken() {
        return this.token;
    }

    private Map<String, List> map = new HashMap<>();

    public TokenProperty() {

    }

    public static class Token {
        private String audiences;
        private String issuerUri;
        public Token() {
        }

        public String getAudiences() {
            return audiences;
        }

        public void setAudiences(String audiences) {
            this.audiences = audiences;
        }

        public String getIssuerUri() {
            return issuerUri;
        }

        public void setIssuerUri(String issuerUri) {
            this.issuerUri = issuerUri;
        }

        @Override
        public String toString() {
            return "Token{" +
                    "audiences=" + audiences +
                    ", issuerUri='" + issuerUri + '\'' +
                    '}';
        }
    }
}
