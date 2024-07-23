package me.sonam.security.util;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
@ConfigurationProperties
public class TokenRequestFilter {
    private final List<RequestFilter> requestFilters = new ArrayList<>();

    public List<RequestFilter> getRequestFilters() {
        return requestFilters;
    }

    private Map<String, List> map = new HashMap<>();

    public TokenRequestFilter() {

    }

    public static class RequestFilter {
        private String in;
        private String out;
        private String httpMethods;
        private Set<String> httpMethodSet = new HashSet<>();
        private Set<String> inSet = new HashSet<>();
        private Set<String> outSet = new HashSet<>();
        private AccessToken accessToken;

        public RequestFilter() {
        }

        public String getIn() {
            return in;
        }

        public String getOut() {
            return out;
        }

        public void setIn(String in) {
            this.in = in;
            String[] inArray = in.split(",");
            inSet = Arrays.stream(inArray).map(String::trim).collect(Collectors.toSet());
        }

        public void setOut(String out) {
            this.out = out;
            String[] outArray = out.split(",");
            outSet = Arrays.stream(outArray).map(String::trim).collect(Collectors.toSet());
        }

        public String getHttpMethods() {
            return httpMethods;
        }
        public Set<String> getHttpMethodSet() {
            return this.httpMethodSet;
        }

        public Set<String> getInSet() {
            return this.inSet;
        }
        public Set<String> getOutSet() {
            return this.outSet;
        }

        public void setHttpMethods(String httpMethods) {
            this.httpMethods = httpMethods;
            String[] httpMethodArray = httpMethods.split(",");
            httpMethodSet = Arrays.stream(httpMethodArray).map(String::trim).map(String::toLowerCase).collect(Collectors.toSet());
        }

        public AccessToken getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(AccessToken accessToken) {
            this.accessToken = accessToken;
        }

        @Override
        public String toString() {
            return "JwtRequest{" +
                    "in='" + in + '\'' +
                    ", inSet='" + inSet + '\'' +
                    ", out='" + out + '\'' +
                    ", outSet='" + outSet + '\'' +
                    ", httpMethods='" + httpMethods +'\'' +
                    ", httpMethodSet='" + httpMethodSet + '\''+
                    ", accessToken='" + accessToken + '\'' +
                    '}';
        }

        public static class AccessToken {
            public static enum JwtOption {
                forward, request, doNothing
            }

            private JwtOption option;
            private String scopes;
            private String base64EncodedClientIdSecret;

            public AccessToken(String option, String scopes, String base64EncodedClientIdSecret) {
                this.option = JwtOption.valueOf(option);
                this.scopes = scopes;
                this.base64EncodedClientIdSecret = base64EncodedClientIdSecret;
            }

            public JwtOption getOption() {
                return option;
            }
            public String getScopes() {
                return scopes;
            }
            public String getBase64EncodedClientIdSecret() {
                return base64EncodedClientIdSecret;
            }

            @Override
            public String toString() {
                return "AccessToken{" +
                        "option=" + option +
                        ", scopes='" + scopes + '\'' +
                        ", base64EncodedClientIdSecret='" + base64EncodedClientIdSecret + '\'' +
                        '}';
            }
        }
    }
}
