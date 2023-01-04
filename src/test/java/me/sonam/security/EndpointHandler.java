package me.sonam.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

/**
 * a basic handler for liveness and readiness endpoints
 */
@Controller
public class EndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(EndpointHandler.class);

    public Mono<ServerResponse> liveness(ServerRequest serverRequest) {
        LOG.debug("liveness check");
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> livenessHead(ServerRequest serverRequest) {
        LOG.debug("liveness head allowed");
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> livenessPost(ServerRequest serverRequest) {
        LOG.debug("liveness post allowed");
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> readiness(ServerRequest serverRequest) {
        LOG.debug("readiness check");
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> readinessPost(ServerRequest serverRequest) {
        LOG.debug("readiness Post check");

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> readinessDelete(ServerRequest serverRequest) {
        LOG.debug("readiness delete requires jwt");

        String authenticationId = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
        LOG.info("authenticate user for authId: {}", authenticationId);

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }
}
