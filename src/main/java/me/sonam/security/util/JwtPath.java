package me.sonam.security.util;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@ConfigurationProperties
public class JwtPath {
    private List<JwtRequest> jwtrequest = new ArrayList();

    public List<JwtRequest> getJwtRequest() {
        return jwtrequest;
    }

    private Map<String, List> map = new HashMap<>();

    public JwtPath() {

    }

    public void mapInAsKey() {
        jwtrequest.forEach(jwtRequest -> {
            if(map.get(jwtRequest.getIn()) == null) {
                map.put(jwtRequest.getIn(), List.of(jwtRequest.getOut()));
            }
            else {
                map.put(jwtRequest.in, List.of(map.get(jwtRequest.getIn()).add(jwtRequest.getOut())));
            }
        });
    }

    public static class JwtRequest {
        private String in;
        private String out;
        private String jwt;
        public enum JwtOption {
            forward, request, doNothing
        }

        public JwtRequest() {
        }

        public String getIn() {
            return in;
        }

        public String getOut() {
            return out;
        }

        public void setIn(String in) {
            this.in = in;
        }

        public void setOut(String out) {
            this.out = out;
        }

        public String getJwt() {
            return jwt;
        }

        public void setJwt(String jwt) {
            this.jwt = jwt;
        }
    }
}
