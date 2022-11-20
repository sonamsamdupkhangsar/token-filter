package me.sonam.security.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URI;
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

    private Map<UUID, Mono<Key>> keyMap = new HashMap<>();


    private WebClient webClient;

    public PublicKeyJwtDecoder(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
        LOG.info("initialized webClient: {}", webClient);
    }

    @Override
    public Mono<Jwt> decode(String jwtToken) throws org.springframework.security.oauth2.jwt.JwtException {
        return getKeyId(jwtToken)
                .flatMap(uuid -> {
                    LOG.info("keyId: {}", uuid);
                    if(keyMap.get(uuid) == null) {
                        return getPublicKeyFromRestService(uuid);
                    }
                    else
                        return keyMap.get(uuid);
                })
                .flatMap(key -> validate(jwtToken, key))
                .onErrorResume(throwable -> {
                    LOG.error("failed to valilidated jwtToken", throwable);
                    return Mono.error(throwable);
                });
    }

    public Mono<Jwt> validate(String jwt, Key publicKey) {
        LOG.info("jwt: {}", jwt);

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
                LOG.info("no expiration date, jwt is valid");
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
            return Mono.error(new JwtException(exception.getMessage()));
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
            LOG.error("failed to created issuerUrl", e);
        }

        return Mono.just(new Jwt("token", claims.getIssuedAt().toInstant(),
                claims.getExpiration().toInstant(),
                Map.of("alg", jwsHeader.getAlgorithm(),
                        "groups", jwsHeader.get("groups"),
                        "clientId", jwsHeader.get("clientId"),
                        "keyId", UUID.fromString(jwsHeader.get("keyId").toString())),
                Map.of("sub", claims.getSubject(),
                        "aud", claims.getAudience(),
                        "iss", issuerUrl)));
    }

    public Key loadPublicKey(String stored)  {
        try {
            byte[] data = Base64.getDecoder().decode(stored.getBytes(StandardCharsets.UTF_8));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePublic(spec);
        }
        catch (GeneralSecurityException e) {
            LOG.error("Exception occured on loading pubic key", e);
            return null;
        }
    }

    public Mono<UUID> getKeyId(String jwtToken) {
        LOG.info("getKeyId for jwtToken by marshaling string to SonamsJwtHeader class");
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String[] chunks = jwtToken.split("\\.");

        String header = new String(decoder.decode(chunks[0]));
        LOG.info("header: {}", header);

        ObjectMapper mapper = new ObjectMapper();

        try {
            SonamsJwtHeader sonamsJwtHeader = mapper.readValue(header, SonamsJwtHeader.class);
            LOG.info("returning keyId: {}", sonamsJwtHeader.getKeyId());
            return Mono.just(sonamsJwtHeader.getKeyId());
        } catch (JsonProcessingException e) {
            LOG.error("failed to convert header to sonams jwt header", e);
            return Mono.empty();
        }

    }

    private Mono<Key> getPublicKeyFromRestService(UUID keyId) {
        LOG.info("get publicKey for keyId");

        final String keyIdString = jwtRestServicePublicKeyId.replace("{keyId}", keyId.toString());

        WebClient.ResponseSpec spec = webClient.get().uri(keyIdString).retrieve();

        return spec.bodyToMono(String.class).map(string -> {
            LOG.info("public key string retrieved {}", string);
            return loadPublicKey(string);
        }).onErrorResume(throwable -> {
            LOG.error("failed to get public key string", throwable);

           return Mono.error(new JwtException("failed to get public key string from endpoint, error: " + throwable.getMessage()));
        });
    }
}
