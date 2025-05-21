package me.sonam.security;


import me.sonam.security.property.PermitPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;

import java.util.Arrays;


@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Autowired
    private PermitPath permitPath;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        LOG.debug("permitPath: {}", permitPath);

        ServerHttpSecurity spec = http
                .exceptionHandling(exceptionHandlingSpec ->
                        exceptionHandlingSpec.accessDeniedHandler(
                                new HttpStatusServerAccessDeniedHandler(HttpStatus.UNAUTHORIZED)))
                .csrf(csrfSpec -> csrfSpec.disable())
                .formLogin(formLoginSpec -> formLoginSpec.disable())
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .authorizeExchange(authorizeExchangeSpec -> {
                    setExchange(authorizeExchangeSpec);
                    authorizeExchangeSpec.anyExchange().authenticated();
                });
        return spec.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())).build();
    }

    private void setExchange(ServerHttpSecurity.AuthorizeExchangeSpec authorizeExchangeSpec) {
         permitPath.getPermitpath().forEach(path -> {

             LOG.debug("path: '{}'", path);

             if (path.getScopes() != null) {
                 LOG.debug("scope is not null");

                 if (path.getHttpMethods() != null) {
                     LOG.debug("apply scope with httpMethods to path");

                     Arrays.stream(path.getScopes().split(","))
                             .forEach(scope -> {
                                 Arrays.stream(path.getHttpMethods().split(",")).forEach(httpMethod -> {
                                     LOG.debug("apply permit for httpMethod: '{}' to path: '{}', with scope: '{}'",
                                             HttpMethod.valueOf(httpMethod.trim()), path.getPath(), scope);
                                     authorizeExchangeSpec.pathMatchers(HttpMethod.POST, path.getPath()).hasAuthority("SCOPE_" + scope);
                                 });
                             });
                 }
                 else {
                     Arrays.stream(path.getScopes().split(","))
                             .forEach(scope -> {
                                 LOG.debug("apply permit to path: '{}', with scope: '{}'", path.getPath(), scope);
                                 authorizeExchangeSpec.pathMatchers(path.getPath()).hasAuthority("SCOPE_" + scope);
                             });
                 }
             }
             else {
                 if (path.getHttpMethods() == null) {
                     LOG.debug("scope is null and path.httpMethods is null so permitAll to path: '{}'", path.getPath());
                     authorizeExchangeSpec.pathMatchers(path.getPath()).permitAll();
                 }
                 else {
                     LOG.debug("permit for individual httpMethods");
                     Arrays.stream(path.getHttpMethods().split(","))
                             .forEach(httpMethod -> {
                                 LOG.debug("permit httpMethod: '{}' to path: '{}'",
                                         httpMethod, path.getPath());
                                 authorizeExchangeSpec.pathMatchers(HttpMethod.valueOf(
                                         httpMethod.trim()), path.getPath()).permitAll();
                             });
                 }
             }
         });
    }

}