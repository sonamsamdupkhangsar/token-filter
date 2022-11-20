package me.sonam.security.jwt.repo.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;

import java.util.UUID;

/**
 * this entity is for storing public private key pair
 */
public class JwtKey implements Persistable<UUID> {
    @Id
    private UUID id;

    private String privateKey;
    private String publicKey;
    private Boolean revoked;

    @Transient
    private boolean newKey;


    public JwtKey(String privateKey, String publicKey) {
        id = UUID.randomUUID();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.revoked = false;
        this.newKey = true;
    }

    public JwtKey() {

    }

    public String getPrivateKey() {
        return this.privateKey;
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public Boolean isRevoked() {
        return this.revoked;
    }

    @Override
    public String toString() {
        return "Key{" +
                "id=" + id +
                ", privateKey='" + privateKey + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", newKey=" + newKey +
                '}';
    }

    @Override
    public UUID getId() {
        return this.id;
    }

    @Override
    public boolean isNew() {
        return newKey;
    }
}
