package me.sonam.security;


import me.sonam.security.property.PermitPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private SecurityContextRepository securityContextRepository;

    @Autowired
    private PermitPath permitPath;

    @Bean
    public SecurityWebFilterChain securitygWebFilterChain(ServerHttpSecurity http) {
        LOG.debug("permitPath: {}", permitPath);
         ServerHttpSecurity.AuthorizeExchangeSpec spec = http
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) ->
                        Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED))
                ).accessDeniedHandler((swe, e) ->
                        Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))
                ).and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll();
         permitPath.getPermitpath().forEach(path -> {
             if (path.getHttpMethods() == null) {
                 spec.pathMatchers(path.getPath()).permitAll();
             }
             else {
                 Arrays.stream(path.getHttpMethods().split(","))
                         .forEach(s ->{
                             LOG.debug("httMethod.valueOf: {}", HttpMethod.valueOf(s.trim()));
                             spec.pathMatchers(HttpMethod.valueOf( s.trim()), path.getPath()).permitAll();});
             }
         });
                return spec.anyExchange().authenticated()
                .and().build();

    }
}