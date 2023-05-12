package me.sonam.security;


import me.sonam.security.property.PermitPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;


@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private SecurityContextRepository securityContextRepository;

    @Autowired
    private PermitPath permitPath;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        LOG.debug("permitPath: {}", permitPath);
         ServerHttpSecurity.AuthorizeExchangeSpec spec = http
                .exceptionHandling()
                .and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS)
                .permitAll();
         permitPath.getPermitpath().forEach(path -> {
             LOG.info("applying permitPath: {}", path);
             if (path.getScopes() != null) {
                 LOG.info("scope is not null, apply scope over httpMethod");
                     Arrays.stream(path.getScopes().split(","))
                             .forEach(s1 -> {
                                 LOG.info("path: '{}', apply hasAuthority(scope) {}", path.getPath(), s1);
                                 spec.pathMatchers(path.getPath()).hasAuthority("SCOPE_"+s1);
                             });
             }
             else {
                 if (path.getHttpMethods() == null) {
                     LOG.info("scope is null and path.httpMethods is null then permitAll to path");
                     spec.pathMatchers(path.getPath()).permitAll();
                 }
                 else {
                     LOG.info("apply individual httpMethods");
                     Arrays.stream(path.getHttpMethods().split(","))
                             .forEach(s -> {
                                 LOG.info("path {}", path.getPath());
                                 LOG.info("add httpPath.valueOf({}): {} to path {}",
                                         s, HttpMethod.valueOf(s.trim()), path.getPath());
                                 spec.pathMatchers(HttpMethod.valueOf(
                                         s.trim()), path.getPath()).permitAll();
                             });
                 }
             }
         });
         return spec.anyExchange().authenticated().and()
                 .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                 .build();

    }
}