package me.sonam.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * For testing the endpoint permitted and not permitted paths
 */
@Configuration
public class EndpointRouter {
    private static final Logger LOG = LoggerFactory.getLogger(EndpointRouter.class);

    @Bean("livenessRouter")
    public RouterFunction<ServerResponse> route(EndpointHandler livenessReadinessHandler) {
        LOG.info("building email router function");
        return RouterFunctions.route(RequestPredicates.GET("/api/health/liveness").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::liveness)
                .andRoute(RequestPredicates.HEAD("/api/health/liveness").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::livenessHead)
                .andRoute(RequestPredicates.POST("/api/health/liveness").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::livenessPost)
                .andRoute(RequestPredicates.GET("/api/health/readiness").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::readiness)
                .andRoute(RequestPredicates.POST("/api/health/readiness").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::readinessPost)
                .andRoute(RequestPredicates.DELETE("/api/health/readiness").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::readinessDelete)
                .andRoute(RequestPredicates.GET("/api/health/passheader").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::passJwtHeaderToBService)
                .andRoute(RequestPredicates.DELETE("/api/health/passheader").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::deletePassJwtHeaderToBService)
                .andRoute(RequestPredicates.GET("/api/health/jwtreceiver").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::jwtHeaderReceiver)
                .andRoute(RequestPredicates.DELETE("/api/health/jwtreceiver").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::jwtHeaderReceiver)
                .andRoute(RequestPredicates.GET("/api/health/calljwtreceiver").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::callJwtHeaderReceiverFromThis)
                .andRoute(RequestPredicates.GET("/api/health/forwardtoken").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::forwardtoken)
                .andRoute(RequestPredicates.GET("/api/health/callthrowerror").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::callthrowError)
                .andRoute(RequestPredicates.GET("/api/health/throwerror").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::throwError)
                .andRoute(RequestPredicates.GET("/api/scope/read").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::scopeEndpoint)
                .andRoute(RequestPredicates.GET("/api/scope/callread").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::callScopeEndpoint)
                .andRoute(RequestPredicates.GET("/api/scope/jwtrequired").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::jwtRequired)
                .andRoute(RequestPredicates.GET("/api/scope/jwtrequired2").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::jwtRequired)
                .andRoute(RequestPredicates.GET("/api/scope/jwtrequired3").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::jwtRequired)
                .andRoute(RequestPredicates.GET("/api/scope/jwtrequired4").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                        livenessReadinessHandler::jwtRequired)
                .andRoute(RequestPredicates.GET("/api/scope/callJwtRequired").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
                livenessReadinessHandler::callJwtRequired);

    }
}
