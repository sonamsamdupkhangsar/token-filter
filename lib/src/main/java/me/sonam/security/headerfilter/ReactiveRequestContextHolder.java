package me.sonam.security.headerfilter;

import me.sonam.security.SecurityException;
import me.sonam.security.util.JwtPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Map;


public class ReactiveRequestContextHolder {
    private static final Logger LOG = LoggerFactory.getLogger(ReactiveRequestContextHolder.class);
    static final Class<ServerHttpRequest> CONTEXT_KEY = ServerHttpRequest.class;

    //set default value to empty if this filter is not added
    //the following is the endpoint for provision of accesstoken from https://{host}:{port}/oauth2/token
    @Value("${auth-server.root:}${auth-server.oauth2token.path:}")
    private String oauth2TokenEndpoint;

    @Value("${auth-server.oauth2token.path:}")
    private String accessTokenPath;

    @Value("${auth-server.oauth2token.grantType:}")
    private String grantType;

    @Autowired
    private JwtPath jwtPath;

    // base64 encoded of clientId and secret if jwt requested for outgoing call
    // based on jwtrequest outbound call.
    @Value("${base64EncodedClientIdAndSecret:}")
    private String base64EncodedClientIdAndSecret;

    private WebClient.Builder webClientBuilder;

    public ReactiveRequestContextHolder(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public static Mono<ServerHttpRequest> getRequest() {
        return Mono.deferContextual(Mono::just)// returns .Mono<ContextView>
                .map(ctx -> ctx.get(CONTEXT_KEY)).map(serverHttpRequest -> {
                    LOG.info("serverHttpRequest: {}", serverHttpRequest.getPath());
                    return serverHttpRequest;
                });
    }

    public ExchangeFilterFunction headerFilter() {
        LOG.info("in headerFilter()");
        return (request, next) -> ReactiveRequestContextHolder.getRequest().flatMap(r ->
                {
                    LOG.info("request path: {}, accessTokenPath: {}", request.url().getPath(), accessTokenPath);

                    if (request.url().getPath().equals(accessTokenPath)) {
                        LOG.info("don't call itself if using the same webclient builder");
                        ClientRequest clientRequest = ClientRequest.from(request).build();
                        return next.exchange(clientRequest);
                    }
                    else {
                        LOG.info("in path: {}, outbound path: {}", r.getPath().pathWithinApplication().value(),
                                request.url().getPath());

                        List<JwtPath.JwtRequest> jwtRequestList = jwtPath.getJwtRequest();
                        for (JwtPath.JwtRequest jwtRequest : jwtRequestList) {
                            if (r.getPath().pathWithinApplication().value().matches(jwtRequest.getIn()) &&
                                    request.url().getPath().matches(jwtRequest.getOut())) {
                                LOG.info("inbound request path and outbound request path both matched");
                                return getClientResponse(jwtRequest, request, r, next);
                            }
                        }
                        LOG.info("no path match found");
                        LOG.info("just do nothing to add to header");
                        ClientRequest clientRequest = ClientRequest.from(request).build();
                        return next.exchange(clientRequest);
                    }
                });

    }

    private Mono<ClientResponse> getClientResponse(JwtPath.JwtRequest jwtRequest, ClientRequest request,
                                                   ServerHttpRequest serverHttpRequest, ExchangeFunction exchangeFunction) {
            if (jwtRequest.getAccessToken().getOption().name().equals(JwtPath.JwtRequest.AccessToken.JwtOption.request.name())) {
                return getJwt(jwtRequest.getAccessToken()).flatMap(s -> {
                    ClientRequest clientRequest = ClientRequest.from(request)
                            .headers(headers -> {
                                headers.set(HttpHeaders.ORIGIN, serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN));
                                headers.setBearerAuth(s);
                                LOG.info("added jwt to header from access token http callout");
                            }).build();
                    return exchangeFunction.exchange(clientRequest);
                });
            }
            else if (jwtRequest.getAccessToken().getOption().name().equals(JwtPath.JwtRequest.AccessToken.JwtOption.forward.name())) {
                ClientRequest clientRequest = ClientRequest.from(request)
                        .headers(headers -> {
                            headers.set(HttpHeaders.ORIGIN, serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN));
                            headers.set(HttpHeaders.AUTHORIZATION,  serverHttpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
                            LOG.info("forward jwt to header from access token http callout");
                        }).build();
                return exchangeFunction.exchange(clientRequest);
            }
            else {
                LOG.info("don't pass headers to downstream web service");
                ClientRequest clientRequest = ClientRequest.from(request).build();
                return exchangeFunction.exchange(clientRequest);
            }
    }

    private Mono<String> getJwt(JwtPath.JwtRequest.AccessToken accessToken) {
        LOG.info("get access token using base64EncodedClientIdAndSecret: {}," +
                " b64ClientIdAndSecret: {}, scopes: {}", oauth2TokenEndpoint,
                accessToken.getBase64EncodedClientIdSecret(),
                accessToken.getScopes());
        final StringBuilder oauthEndpointWithScope = new StringBuilder(oauth2TokenEndpoint);

        MultiValueMap<String, Object> multiValueMap = new LinkedMultiValueMap<>();
        multiValueMap.add("grant_type", grantType);

        if (accessToken.getScopes() != null && !accessToken.getScopes().trim().isEmpty()) {
            List<String> scopeList = Arrays.stream(accessToken.getScopes().split(" ")).toList();
            multiValueMap.add("scopes", scopeList);
        }

        LOG.info("sending oauth2TokenEndpointWithScopes: {}", oauthEndpointWithScope);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(oauthEndpointWithScope.toString())
                .bodyValue(multiValueMap)
                .headers(httpHeaders -> httpHeaders.setBasicAuth(accessToken.getBase64EncodedClientIdSecret()))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.debug("response for '{}' is in map: {}", oauth2TokenEndpoint, map);
            if (map.get("access_token") != null) {
                return map.get("access_token").toString();
            }
            else {
                LOG.error("nothing to return");
                return "nothing";
            }
        }).onErrorResume(throwable -> {
            LOG.error("jwt access token rest call failed: {}", throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new SecurityException(errorMessage));
        });
    }
}