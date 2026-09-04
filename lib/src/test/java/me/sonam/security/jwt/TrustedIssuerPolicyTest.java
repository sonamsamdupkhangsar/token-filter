package me.sonam.security.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TrustedIssuerPolicyTest {
    @Test
    void explicitIssuerListAcceptsOnlyExactIssuer() {
        TrustedIssuerPolicy policy = new TrustedIssuerPolicy(
                Set.of("https://acme.openissuer.com/issuer"),
                Set.of("openissuer.com"));

        assertDoesNotThrow(() -> policy.assertTrusted("https://acme.openissuer.com/issuer"));
        assertThrows(BadJwtException.class,
                () -> policy.assertTrusted("https://other.openissuer.com/issuer"));
        assertThrows(BadJwtException.class,
                () -> policy.assertTrusted("https://acme.openissuer.com/other"));
    }

    @Test
    void suffixFallbackRemainsAvailableWhenExplicitListIsEmpty() {
        TrustedIssuerPolicy policy = new TrustedIssuerPolicy(
                Set.of(),
                Set.of("openissuer.com"));

        assertDoesNotThrow(() -> policy.assertTrusted("https://acme.openissuer.com/issuer"));
        assertThrows(BadJwtException.class,
                () -> policy.assertTrusted("https://openissuer.com.attacker.example/issuer"));
    }

    @Test
    void rejectsMalformedIssuerUris() {
        TrustedIssuerPolicy policy = new TrustedIssuerPolicy(Set.of(), Set.of("openissuer.com"));

        assertThrows(BadJwtException.class, () -> policy.assertTrusted("not-a-uri"));
        assertThrows(BadJwtException.class,
                () -> policy.assertTrusted("https://acme.openissuer.com/issuer?redirect=attacker"));
    }

    @Test
    void rejectsMalformedExplicitConfiguration() {
        assertThrows(BadJwtException.class,
                () -> new TrustedIssuerPolicy(Set.of("not-a-uri"), Set.of()));
    }
}
