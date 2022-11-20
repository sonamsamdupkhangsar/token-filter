package me.sonam.security.jwt;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.*;
import me.sonam.security.jwt.repo.JwtKeyRepository;
import me.sonam.security.jwt.repo.entity.JwtKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * This class will create a JWT string token.
 * User needs to call the interface method {@code #createJwtKey method} with the params.
 * The user params are set in the JWT header such as 'groups', 'clientId', and 'keyId'.
 */
@Service
public class PublicKeyJwtCreator implements JwtCreator {

    private static final Logger LOG = LoggerFactory.getLogger(PublicKeyJwtCreator.class);

    @Value("${jwt.issuer}")
    private String issuer;

    @Autowired
    private JwtKeyRepository jwtKeyRepository;

    public PublicKeyJwtCreator() {
    }

    public void checkForKey() {
        Mono<JwtKey> keyMono = jwtKeyRepository.findTop1ByRevokedIsFalse();
        keyMono.switchIfEmpty(generateKey()).subscribe(jwtKey ->LOG.info("initialize key"));
    }

    private Mono<JwtKey> generateKey() {
        LOG.info("generate key");
        try {
            JwtKey jwtKey = createJwtKey();
            return jwtKeyRepository.save(jwtKey);
        } catch (Exception e) {
            LOG.error("failed to generate rsa public/private keys", e);
            return Mono.error(new io.jsonwebtoken.JwtException("failed to generate key"));
        }
    }

    @Override
    public Mono<String> create(String clientId, String groupNames, String subject, String audience, int calendarField, int calendarValue) {
        checkForKey();

        return jwtKeyRepository.findTop1ByRevokedIsFalse().flatMap(jwtKey -> {
            Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            Date issueDate = calendar.getTime();

            calendar.add(calendarField, calendarValue);
            Date expireDate = calendar.getTime();

            byte[] privateByteKey  = Base64.getDecoder().decode(jwtKey.getPrivateKey());
            LOG.info("private byte key:: {}" + privateByteKey);

            Key privateKey = loadPrivateKey(jwtKey.getPrivateKey());

            String jwt = Jwts.builder()
                    .setSubject(subject)
                    .setIssuer(issuer)
                    .setAudience(audience)
                    .setIssuedAt(issueDate)
                    .setHeaderParam("groups", groupNames)
                    .setHeaderParam("clientId", clientId)
                    .setHeaderParam("keyId", jwtKey.getId())
                    .setExpiration(expireDate)
                    .setId(UUID.randomUUID().toString())
                    .signWith(SignatureAlgorithm.RS512, privateKey)
                    .compact();

            LOG.info("returning jwt");
            return Mono.just(jwt);
        }).switchIfEmpty(Mono.just("No key found"));
    }

    private static Map<String, Object> generateRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return Map.of("private", keyPair.getPrivate(), "public", keyPair.getPublic());
    }

    public Key loadPrivateKey(String stored) {
        try {
            PKCS8EncodedKeySpec keySpec =
                    new PKCS8EncodedKeySpec(
                            Base64.getDecoder().decode(stored.getBytes(StandardCharsets.UTF_8)));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(keySpec);
        }
        catch (GeneralSecurityException gse) {
            LOG.error("exception occured", gse);
            return null;
        }
    }

    public JwtKey createJwtKey() throws Exception {
        Map<String, Object> rsaKeys = generateRSAKeys();
        PrivateKey privateKey = (PrivateKey) rsaKeys.get("private");

        byte[] prbytes = privateKey.getEncoded();
        byte[] pubytes = privateKey.getEncoded();
        LOG.info("private key in bytes: {}", prbytes);
        LOG.info("public key bytes: {}", pubytes);


        final String publicKeyString = Base64.getEncoder().encodeToString(((PublicKey) rsaKeys.get("public")).getEncoded());
        final String privateKeyString = Base64.getEncoder().encodeToString(((PrivateKey) rsaKeys.get("private")).getEncoded());

        LOG.info("private key: {}",privateKeyString);
        LOG.info("public key: {}", publicKeyString);

        JwtKey jwtKey = new JwtKey(privateKeyString, publicKeyString);
        return jwtKey;
    }
}
