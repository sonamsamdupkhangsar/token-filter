package me.sonam.security;

import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Component
@AllArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationManager.class);

    @Autowired
    private ReactiveJwtDecoder jwtDecoder;

    public AuthenticationManager() {
        LOG.debug("instantiating authenticationManager");
    }

    @Override
    @SuppressWarnings("unchecked")
    public Mono<Authentication> authenticate(Authentication authentication) {
        LOG.info("authentication: {},\n authorities: {}", authentication, authentication.getAuthorities());
        String authToken = authentication.getCredentials().toString();
        LOG.info("authToken: {}", authToken);

        return jwtDecoder.decode(authToken).map(jwt -> {
            LOG.debug("returning UsernamePasswordAuthenticationToken: jwt.subject: {}", jwt.getSubject());
            List<GrantedAuthority> list = new ArrayList<>();
            list.add(new SimpleGrantedAuthority("API_ACCESS"));
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(jwt.getSubject(), null, list);

            SecurityContextHolder.getContext()
                    .setAuthentication(usernamePasswordAuthenticationToken);
            return usernamePasswordAuthenticationToken;
        });
    }
}