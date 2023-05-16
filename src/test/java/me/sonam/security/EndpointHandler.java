package me.sonam.security;

import jakarta.annotation.PostConstruct;
import me.sonam.security.headerfilter.ReactiveRequestContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

//import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

/**
 * a basic handler for liveness and readiness endpoints
 */
@Controller
public class EndpointHandler {
    private static final Logger LOG = LoggerFactory.getLogger(EndpointHandler.class);

    @Value("${jwt-receiver.root}${jwt-receiver.receiver}")
    private String jwtReceiver;

    @Value("${jwt-receiver.root}")
    private String localHost;

    @Autowired
    private ReactiveRequestContextHolder reactiveRequestContextHolder;

    private WebClient.Builder webClientBuilder;

    public EndpointHandler(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @PostConstruct
    public void setWebClient() {
        webClientBuilder.filter(reactiveRequestContextHolder.headerFilter()).build();
    }

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

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> passJwtHeaderToBService(ServerRequest serverRequest) {
        LOG.debug("pass jwt header to receiveJwtHeader endpoint");

        return callEndpoint(jwtReceiver).flatMap(s ->
                ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(getMap(Pair.of("message", s)))
        ).onErrorResume(throwable ->{
            LOG.error("endpoint call failed: {}", throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new SecurityException(errorMessage));
        } );
    }

    private Mono<String> callEndpoint(final String endpoint) {
        LOG.info("call endpoint: {}", endpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(endpoint)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("response for endpoint '{}' is: {}",endpoint, map);
            LOG.info("got response message: {}", map.get("message"));
            return map.get("message").toString();
        }).onErrorResume(throwable -> {
            LOG.error("endpoint: '{}' rest call failed: {}", endpoint, throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new SecurityException(errorMessage));
        });
    }

    public Mono<ServerResponse> callJwtHeaderReceiverFromThis(ServerRequest serverRequest) {
        LOG.debug("in callJwtHeaderReceiverFromThis, just call jwtReceiver endpoint but without jwt");

        return callEndpoint(jwtReceiver).flatMap(s ->
                ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(getMap(Pair.of("message", s)))
        ).onErrorResume(throwable ->{
            LOG.error("endpoint call failed: {}", throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new SecurityException(errorMessage));
        } );
    }

    public Mono<ServerResponse> forwardtoken(ServerRequest serverRequest) {
        LOG.debug("in forwardtoken, just call jwtReceiver endpoint, filter should forward jwt token");

        return callEndpoint(jwtReceiver).flatMap(s ->
                ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(getMap(Pair.of("message", s)))
        ).onErrorResume(throwable ->{
            LOG.error("endpoint call failed: {}", throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new SecurityException(errorMessage));
        } );
    }

    public Mono<ServerResponse> jwtHeaderReceiver(ServerRequest serverRequest) {
        LOG.debug("in jwt header receiver service: {}", serverRequest.headers().firstHeader(HttpHeaders.AUTHORIZATION));

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            LOG.error("no authentication found");
        }
        else {
            String authenticationId = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
            LOG.info("authenticate user for authId: {}", authenticationId);
        }
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> notPassJwtHeader(ServerRequest serverRequest) {
        LOG.debug("readiness delete requires jwt");

        String authenticationId = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
        LOG.info("authenticate user for authId: {}", authenticationId);

        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }
    public Mono<ServerResponse> callthrowError(ServerRequest serverRequest) {
        LOG.debug("call throw error");

        final String endpoint = localHost+"/api/health/throwerror";

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(endpoint)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();

        return responseSpec.bodyToMono(Map.class).
            flatMap(s ->
                    ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(getMap(Pair.of("message", s.toString()))))
        .onErrorResume(throwable -> {
            LOG.error("endpoint: '{}' rest call failed: {}", endpoint, throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new SecurityException(errorMessage));
        });
    }

    public Mono<ServerResponse> throwError(ServerRequest serverRequest) {
        LOG.info("throwing error from path /api/health/throwerror");
        return ServerResponse.badRequest().bodyValue("throwing error");
    }

    public Mono<ServerResponse> scopeEndpoint(ServerRequest serverRequest) {
        LOG.debug("scope read check endpoint");
        return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).build();
    }

    public Mono<ServerResponse> callScopeEndpoint(ServerRequest serverRequest) {
        LOG.debug("this will call scopeEndpoint with a jwt token from localhost environment");
        final String apiScopeReadEndpoint = localHost + "/api/scope/read";

        return webClientBuilder.build().get().uri(apiScopeReadEndpoint)
                .retrieve()
                .bodyToMono(String.class).flatMap(s -> {
                    LOG.info("response from api/scope/read is {}", s);
                    return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(s);
                })
                .onErrorResume(throwable -> {
                    LOG.error("endpoint: '{}' rest call failed: {}", apiScopeReadEndpoint, throwable.getMessage());
                    String errorMessage = throwable.getMessage();

                    if (throwable instanceof WebClientResponseException) {
                        WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                        LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                        errorMessage = webClientResponseException.getResponseBodyAsString();
                    }
                    return Mono.error(new SecurityException(errorMessage));
                });
    }

    public static Map<String, String> getMap(Pair<String, String>... pairs){

        Map<String, String> map = new HashMap<>();

        for(Pair<String, String> pair: pairs) {
            map.put(pair.getFirst(), pair.getSecond());
        }
        return map;

    }
}
