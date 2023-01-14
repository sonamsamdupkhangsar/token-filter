package me.sonam.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public class JwtBody {
    private static final Logger LOG = LoggerFactory.getLogger(JwtBody.class);

    public enum RoleEnum {
        user, admin
    }

    private UUID keyId;
    private String sub;
    private String scope;
    private String clientId;
    private String aud;
    private long expiresInSeconds;

    private String exp;
    private String iat;
    private String jti;
    private String iss;
    private String role;
    private String groups;
    public JwtBody() {

    }

    public JwtBody(String sub, String scope, String clientId, String aud, String role, String groups, long expiresInSeconds) {
        this.sub = sub;

        this.scope = scope;
        this.clientId = clientId;
        this.aud = aud;
        this.expiresInSeconds = expiresInSeconds;
        this.role = role;
        this.groups = groups;
    }

    public String getSub() {
        return sub;
    }

    public UUID getKeyId() {
        return keyId;
    }

    public String getScope() {
        return scope;
    }

    public String getClientId() {
        return clientId;
    }

    public String getAud() {
        return aud;
    }

    public void setKeyId(UUID keyId) {
        this.keyId = keyId;
    }

    public String getIss() {
        return iss;
    }

    public String getExp() {
        return exp;
    }

    public String getJti() {
        return jti;
    }

    public String getIat() {
        return iat;
    }

    public String getRole() {
        return role;
    }

    public String getGroups() {
        return groups;
    }

    @Override
    public String toString() {
        return "JwtBody{" +
                "keyId=" + keyId +
                ", sub='" + sub + '\'' +
                ", scope='" + scope + '\'' +
                ", clientId='" + clientId + '\'' +
                ", aud='" + aud + '\'' +
                ", expiresInSeconds=" + expiresInSeconds +
                ", exp='" + exp + '\'' +
                ", iat='" + iat + '\'' +
                ", jti='" + jti + '\'' +
                ", iss='" + iss + '\'' +
                ", role='" + role + '\'' +
                ", groups='" + groups + '\'' +
                '}';
    }

    public long getExpiresInSeconds() {
        return expiresInSeconds;
    }
}
