package me.sonam.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties
public class AllowProps {

    private List<Path> allow = new ArrayList<>();

    public List<Path> getAllow() {
        return allow;
    }

    public void setAllow(List<Path> allow) {
        this.allow = allow;
    }

    @Override
    public String toString() {
        return "Allow{" +
                "paths=" + allow +
                '}';
    }

    public static class Path {
        private String path;
        private String httpMethod;

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String getHttpMethod() {
            return httpMethod;
        }

        public void setHttpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
        }

        @Override
        public String toString() {
            return "AllowPath{" +
                    "path='" + path + '\'' +
                    ", httpMethods='" + httpMethod + '\'' +
                    '}';
        }
    }

}
