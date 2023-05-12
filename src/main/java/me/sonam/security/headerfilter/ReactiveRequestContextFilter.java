package me.sonam.security.headerfilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;


import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)

public class ReactiveRequestContextFilter implements WebFilter {
    private static final Logger LOG = LoggerFactory.getLogger(ReactiveRequestContextFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        LOG.debug("request: {}", request.getPath());

        return chain.filter(exchange).contextWrite(context -> context.put(ReactiveRequestContextHolder.CONTEXT_KEY, request));
    }
}