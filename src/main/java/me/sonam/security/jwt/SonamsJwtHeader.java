package me.sonam.security.jwt;


import lombok.Getter;

import java.util.UUID;

/**
 * class to extract Jwt header into this class type.
 */
@Getter
public class SonamsJwtHeader {
    private String groups;
    private String clientId;
    private UUID keyId;
    private String alg;

    public SonamsJwtHeader() {

    }

    @Override
    public String toString() {
        return "SonamsJwtHeader{" +
                "groups='" + groups + '\'' +
                ", clientId='" + clientId + '\'' +
                ", keyId=" + keyId +
                ", alg='" + alg + '\'' +
                '}';
    }
}

