package me.sonam.security.headerfilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;

public class ReactiveRequestContextHolder {
    private static final Logger LOG = LoggerFactory.getLogger(ReactiveRequestContextHolder.class);
    static final Class<ServerHttpRequest> CONTEXT_KEY = ServerHttpRequest.class;

    public static Mono<ServerHttpRequest> getRequest() {
        return Mono.subscriberContext()
                .map(ctx -> ctx.get(CONTEXT_KEY));
    }

    public static ExchangeFilterFunction headerFilter() {
        return (request, next) -> ReactiveRequestContextHolder.getRequest()
                .flatMap(r -> {
                    ClientRequest clientRequest = ClientRequest.from(request)
                            .headers(headers -> {
                                headers.set(HttpHeaders.ORIGIN, r.getHeaders().getFirst(HttpHeaders.ORIGIN));
                                headers.set(HttpHeaders.AUTHORIZATION, r.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));

                                LOG.info("added authorization header: {}", r.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
                            })
                            .build();
                    return next.exchange(clientRequest);
                });
    }
}