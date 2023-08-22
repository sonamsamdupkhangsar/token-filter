package me.sonam.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

public class AudienceValidator implements OAuth2TokenValidator<Jwt> {
    private static final Logger LOG = LoggerFactory.getLogger(AudienceValidator.class);

    private List<String> audiences;

    public AudienceValidator(List<String> audiences) {
        this.audiences = audiences;
    }

    OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing", null);

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        LOG.info("checking jwt for audience: {}", audiences);

        if (jwt.getAudience().stream().anyMatch(audiences::contains) ) {
            LOG.info("token contains a match from accepted audience: {}", audiences);
            return OAuth2TokenValidatorResult.success();
        } else {
            LOG.error("token does not contain any match from accepted audiences: {}", audiences);
            return OAuth2TokenValidatorResult.failure(error);
        }

    }
}
