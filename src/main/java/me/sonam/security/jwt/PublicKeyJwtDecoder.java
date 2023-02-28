package me.sonam.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import me.sonam.security.JwtBody;
import me.sonam.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * This class will decode a JWT token in string form.  It will build the
 * OAuth2 JWT token form and retrun to the caller.
 * This implementation of {@link ReactiveJwtDecoder} is used by {@link me.sonam.security.AuthenticationManager}
 * for decoding a string JWT token and returning a OAuth2 JWT token type.
 */
@Component
public class PublicKeyJwtDecoder implements ReactiveJwtDecoder  {
    private static final Logger LOG = LoggerFactory.getLogger(PublicKeyJwtDecoder.class);

    @Value("${jwt-rest-service-public-key-id}")
    private String jwtRestServicePublicKeyId;

    private Map<UUID, Key> keyMap = new HashMap<>();


    private WebClient webClient;

    public PublicKeyJwtDecoder(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
        LOG.trace("initialized webClient: {}", webClient);
    }

    @Override
    public Mono<Jwt> decode(String jwtToken) throws org.springframework.security.oauth2.jwt.JwtException {
        return getKeyId(jwtToken)
                .flatMap(uuid -> {
                    LOG.info("keyId: {}", uuid);
                    if(keyMap.get(uuid) == null) {
                        return getPublicKeyFromRestService(uuid).flatMap(key -> {
                            keyMap.put(uuid, key);
                            LOG.info("stored monoKey for uuid: {}", uuid);
                            return Mono.just(key);
                        });
                    }
                    else {
                        LOG.info("return monoKey from keymap for uuid: {}", uuid);
                        return Mono.just(keyMap.get(uuid));
                    }
                })
                .flatMap(key -> validate(jwtToken, key))
                .onErrorResume(throwable -> {
                    LOG.error("failed to valilidated jwtToken, error: {}", throwable.getMessage());
                    return Mono.error(new SecurityException("failed to validate jwt token"));
                });
    }

    public Mono<Jwt> validate(String jwt, Key publicKey) {
        LOG.debug("validate jwt: {}", jwt);

        if (jwt == null || jwt.isEmpty()) {
            LOG.error("cannot authenticate a null jwt token");
            return Mono.error(new JwtException("jwt not found"));
        }

        try {
            Claims claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwt)
                    .getBody();

            JwsHeader jwsHeader = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwt).getHeader();

            Date expirationDate = claims.getExpiration();

            if (expirationDate == null) {
                LOG.debug("no expiration date, jwt is valid");
                return getJwt(jwsHeader, claims);
            }
            else {
                Calendar calendar = Calendar.getInstance();
                Date currentDate = calendar.getTime();

                if (currentDate.before(expirationDate)) {
                    LOG.debug("jwt is valid");

                    return getJwt(jwsHeader, claims);
                }
                else {
                    LOG.debug("token has expired, ask user to renew");
                    return Mono.empty();
                }
            }
        } catch (SignatureException signatureException) {
            return Mono.error(new JwtException(signatureException.getMessage()));
        } catch (ExpiredJwtException exception) {
            LOG.debug("jwt has expired, error: {}", exception.getMessage());

            return Mono.error(new JwtException("Jwt expired at "+ exception.getClaims().getExpiration()));
        }
        catch (MalformedJwtException malformedJwtException) {
            return Mono.error(new JwtException(malformedJwtException.getMessage()));
        }
    }

    private Mono<Jwt> getJwt(JwsHeader jwsHeader, Claims claims) {
        URL issuerUrl = null;
        try {
            issuerUrl = new URL(claims.getIssuer());
        }
        catch (Exception e) {
            LOG.error("failed to created issuerUrl, error: {}", e.getMessage());
        }

        return Mono.just(new Jwt("token", claims.getIssuedAt().toInstant(),
                claims.getExpiration().toInstant(),
                Map.of("alg", jwsHeader.getAlgorithm()),
                Map.of("sub", claims.getSubject(),
                        "clientId", claims.get("clientId"),
                        "aud", claims.getAudience(),
                        "scope", claims.get("scope"),
                        "iss", issuerUrl,
                        "role", claims.get("role"),
                        "groups", claims.get("groups"),
                        "keyId", UUID.fromString(claims.get("keyId").toString()))));
    }

    public Key loadPublicKey(String stored)  {
        try {
            byte[] data = Base64.getDecoder().decode(stored.getBytes(StandardCharsets.UTF_8));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePublic(spec);
        }
        catch (GeneralSecurityException e) {
            LOG.error("Exception occured on loading pubic key, error: {}", e.getMessage());
            return null;
        }
    }

    public Mono<UUID> getKeyId(String jwtToken) {
        LOG.debug("getKeyId for jwtToken by marshaling string to JwtBody class");
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String[] chunks = jwtToken.split("\\.");

        String payload = new String(decoder.decode(chunks[1]));
        LOG.debug("payload: {}", payload);

        ObjectMapper mapper = new ObjectMapper();

        try {
            JwtBody jwtBody = mapper.readValue(payload, JwtBody.class);
            LOG.debug("returning keyId: {}", jwtBody.getKeyId());
            return Mono.just(jwtBody.getKeyId());
        } catch (JsonProcessingException e) {
            LOG.error("failed to convert header to sonams jwt header, error: {}", e.getMessage());
            return Mono.empty();
        }

    }

    private Mono<Key> getPublicKeyFromRestService(UUID keyId) {
        LOG.debug("get publicKey for keyId");

        final String keyIdString = jwtRestServicePublicKeyId.replace("{keyId}", keyId.toString());

        WebClient.ResponseSpec spec = webClient.get().uri(keyIdString).retrieve();

        return spec.bodyToMono(Map.class).map(map -> {
            LOG.debug("public key string retrieved {}", map.get("key"));
            return loadPublicKey(map.get("key").toString());
        }).onErrorResume(throwable -> {
            LOG.error("failed to get public key string, error: {}", throwable.getMessage());

           return Mono.error(new JwtException("failed to get public key string from endpoint, error: " + throwable.getMessage()));
        });
    }
}
