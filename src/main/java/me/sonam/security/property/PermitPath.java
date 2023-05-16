package me.sonam.security.property;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties
public class PermitPath {
    private List<Path> permitpath = new ArrayList();

    public List<Path> getPermitpath() {
        return permitpath;
    }

    public void setPermitpath(List<Path> permitpath) {
        this.permitpath = permitpath;
    }

    @Override
    public String toString() {
        return "Permit{" +
                "path=" + permitpath +
                '}';
    }

    public static class Path {
        private String path;
        // if scopes is defined then it will take precedence over httpMethods values
        private String scopes;
        private String httpMethods;

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public String getHttpMethods() {
            return httpMethods;
        }

        public void setHttpMethods(String httpMethods) {
            this.httpMethods = httpMethods;
        }

        public String getScopes() {
            return scopes;
        }

        public void setScopes(String scopes) {
            this.scopes = scopes;
        }

        @Override
        public String toString() {
            return "PermitPath{" +
                    "path='" + path + '\'' +
                    ", httpMethods='" + httpMethods + '\'' +
                    ", scopes='" + scopes + '\'' +
                    '}';
        }
    }
}
