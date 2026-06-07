package me.sonam.security.jwt;

import com.nimbusds.jwt.JWTParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Configuration
public class MultiIssuerJwtDecoderConfig {
    private static final String JWKS_PATH = "/oauth2/jwks";

    @Bean
    @ConditionalOnMissingBean(ReactiveJwtDecoder.class)
    public ReactiveJwtDecoder reactiveJwtDecoder(
            @Value("${openissuer.trusted-issuer-host-suffixes:openissuer.test,openissuer.com}") String trustedIssuerHostSuffixes) {
        return new MultiIssuerReactiveJwtDecoder(parseTrustedSuffixes(trustedIssuerHostSuffixes));
    }

    private Set<String> parseTrustedSuffixes(String trustedIssuerHostSuffixes) {
        return Arrays.stream(trustedIssuerHostSuffixes.split(","))
                .map(String::trim)
                .filter(suffix -> !suffix.isEmpty())
                .collect(Collectors.toSet());
    }

    private static final class MultiIssuerReactiveJwtDecoder implements ReactiveJwtDecoder {
        private final Set<String> trustedIssuerHostSuffixes;
        private final Map<String, ReactiveJwtDecoder> decodersByIssuer = new ConcurrentHashMap<>();

        private MultiIssuerReactiveJwtDecoder(Set<String> trustedIssuerHostSuffixes) {
            this.trustedIssuerHostSuffixes = trustedIssuerHostSuffixes;
        }

        @Override
        public Mono<Jwt> decode(String token) throws JwtException {
            String issuer = issuer(token);
            assertTrustedIssuer(issuer);
            return decodersByIssuer.computeIfAbsent(issuer, this::decoderForIssuer).decode(token);
        }

        private String issuer(String token) {
            try {
                String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
                if (issuer == null || issuer.isBlank()) {
                    throw new JwtException("missing issuer claim");
                }
                return issuer;
            }
            catch (ParseException e) {
                throw new JwtException("failed to parse jwt issuer", e);
            }
        }

        private void assertTrustedIssuer(String issuer) {
            String host = URI.create(issuer).getHost();
            boolean trusted = host != null && trustedIssuerHostSuffixes.stream()
                    .anyMatch(suffix -> host.equals(suffix) || host.endsWith("." + suffix));
            if (!trusted) {
                throw new JwtException("untrusted issuer host: " + host);
            }
        }

        private ReactiveJwtDecoder decoderForIssuer(String issuer) {
            NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(issuer + JWKS_PATH).build();
            jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
            return jwtDecoder;
        }
    }
}
