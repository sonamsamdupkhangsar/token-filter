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
            @Value("${openissuer.trusted-issuers:}") String trustedIssuers,
            @Value("${openissuer.trusted-issuer-host-suffixes:openissuer.test,openissuer.com}") String trustedIssuerHostSuffixes) {
        return new MultiIssuerReactiveJwtDecoder(
                parseCommaSeparated(trustedIssuers),
                parseCommaSeparated(trustedIssuerHostSuffixes));
    }

    private Set<String> parseCommaSeparated(String values) {
        return Arrays.stream(values.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toSet());
    }

    private static final class MultiIssuerReactiveJwtDecoder implements ReactiveJwtDecoder {
        private final TrustedIssuerPolicy trustedIssuerPolicy;
        private final Map<String, ReactiveJwtDecoder> decodersByIssuer = new ConcurrentHashMap<>();

        private MultiIssuerReactiveJwtDecoder(Set<String> trustedIssuers,
                                              Set<String> trustedIssuerHostSuffixes) {
            this.trustedIssuerPolicy = new TrustedIssuerPolicy(trustedIssuers, trustedIssuerHostSuffixes);
        }

        @Override
        public Mono<Jwt> decode(String token) throws JwtException {
            String issuer = issuer(token);
            trustedIssuerPolicy.assertTrusted(issuer);
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

        private ReactiveJwtDecoder decoderForIssuer(String issuer) {
            NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(issuer + JWKS_PATH).build();
            jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
            return jwtDecoder;
        }
    }
}
