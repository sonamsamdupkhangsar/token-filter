package me.sonam.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.*;

/**
 * For testing the endpoint permitted and not permitted paths
 */
@Configuration
public class EndpointRouter {
    private static final Logger LOG = LoggerFactory.getLogger(EndpointRouter.class);

    @Bean("livenessRouter")
    public RouterFunction<ServerResponse> route(EndpointHandler livenessReadinessHandler) {
        LOG.info("building email router function");
        return RouterFunctions.route(GET("/api/health/liveness").and(accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::liveness)
                .andRoute(HEAD("/api/health/liveness").and(accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::livenessHead)
                .andRoute(POST("/api/health/liveness").and(accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::livenessPost)
                .andRoute(GET("/api/health/readiness").and(accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::readiness)
                .andRoute(POST("/api/health/readiness").and(accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::readinessPost)
                .andRoute(DELETE("/api/health/readiness").and(accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::readinessDelete);

    }
}
