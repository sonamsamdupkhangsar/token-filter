package me.sonam.security.jwt;

import org.springframework.security.oauth2.jwt.BadJwtException;

import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Restricts lazy JWT decoder creation to configured issuers.
 *
 * <p>An explicit issuer allowlist takes precedence over the legacy hostname-suffix
 * configuration. The suffix fallback exists for compatibility while applications
 * migrate to {@code openissuer.trusted-issuers}.</p>
 */
final class TrustedIssuerPolicy {
    private final Set<String> trustedIssuers;
    private final Set<String> trustedIssuerHostSuffixes;

    TrustedIssuerPolicy(Set<String> trustedIssuers, Set<String> trustedIssuerHostSuffixes) {
        this.trustedIssuers = Set.copyOf(trustedIssuers);
        this.trustedIssuerHostSuffixes = trustedIssuerHostSuffixes.stream()
                .map(suffix -> suffix.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        this.trustedIssuers.forEach(TrustedIssuerPolicy::validatedIssuerUri);
    }

    void assertTrusted(String issuer) {
        URI issuerUri = validatedIssuerUri(issuer);
        if (!trustedIssuers.isEmpty()) {
            if (!trustedIssuers.contains(issuer)) {
                throw new BadJwtException("untrusted issuer: " + issuer);
            }
            return;
        }

        String host = issuerUri.getHost();
        boolean trusted = host != null && trustedIssuerHostSuffixes.stream()
                .anyMatch(suffix -> host.equalsIgnoreCase(suffix)
                        || host.toLowerCase(Locale.ROOT).endsWith("." + suffix));
        if (!trusted) {
            throw new BadJwtException("untrusted issuer host: " + host);
        }
    }

    private static URI validatedIssuerUri(String issuer) {
        try {
            URI uri = URI.create(issuer);
            if (!uri.isAbsolute() || uri.getHost() == null
                    || !("https".equalsIgnoreCase(uri.getScheme())
                    || "http".equalsIgnoreCase(uri.getScheme()))
                    || uri.getQuery() != null || uri.getFragment() != null) {
                throw new BadJwtException("invalid issuer URI: " + issuer);
            }
            return uri;
        }
        catch (IllegalArgumentException exception) {
            throw new BadJwtException("invalid issuer URI: " + issuer, exception);
        }
    }
}
