package me.sonam.security.property;

import me.sonam.security.util.JwtPath;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
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
        private List<String> audiences = new ArrayList<>();
        private String issuerUri;
        public Token() {
        }

        public List<String> getAudiences() {
            return audiences;
        }

        public void setAudiences(List<String> audiences) {
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
