package me.sonam.security.headerfilter;

import me.sonam.security.SecurityException;
import me.sonam.security.util.TokenRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.*;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;


public class ReactiveRequestContextHolder {
    private static final Logger LOG = LoggerFactory.getLogger(ReactiveRequestContextHolder.class);
    static final Class<ServerHttpRequest> CONTEXT_KEY = ServerHttpRequest.class;

    //set default value to empty if this filter is not added
    //the following is the endpoint for provision of accesstoken from https://{host}:{port}/oauth2/token
    @Value("${auth-server.root:}${auth-server.context-path:}${auth-server.oauth2token.path:}")
    private String oauth2TokenEndpoint;

    @Value("${auth-server.context-path:}${auth-server.oauth2token.path:}")
    private String accessTokenPath;

    @Value("${auth-server.oauth2token.grantType:}")
    private String grantType;

    @Autowired
    private TokenRequestFilter tokenRequestFilter;

    // base64 encoded of clientId and secret if jwt requested for outgoing call
    // based on jwtrequest outbound call.
    @Value("${base64EncodedClientIdAndSecret:}")
    private String base64EncodedClientIdAndSecret;

    private final WebClient.Builder webClientBuilder;
    private final int tokenExpireSeconds;

    public ReactiveRequestContextHolder(WebClient.Builder webClientBuilder, int tokenExpireSeconds) {
        this.webClientBuilder = webClientBuilder;
        this.tokenExpireSeconds = tokenExpireSeconds;
    }

    public static Mono<ServerHttpRequest> getRequest() {
        return Mono.deferContextual(Mono::just)// returns .Mono<ContextView>
                .map(ctx -> ctx.get(CONTEXT_KEY)).map(serverHttpRequest -> {
                    return serverHttpRequest;
                });
    }

    public ExchangeFilterFunction headerFilter() {
        LOG.info("in headerFilter()");
        return (request, next) -> ReactiveRequestContextHolder.getRequest().flatMap(r ->
        {
            //r == inbound request, request = outbound request
            LOG.debug("inbound path: {}, outbound path: {}, inbound method: {}, outbound method: {}", r.getPath().pathWithinApplication().value(),
                    request.url().getPath(), r.getMethod().name(), request.method().name());

            LOG.debug("accessTokenPath: {}", accessTokenPath);

            if (request.url().getPath().equals(accessTokenPath)) {
                LOG.debug("don't call itself if using the same webclient builder");
                ClientRequest clientRequest = ClientRequest.from(request).build();
                return next.exchange(clientRequest);
            } else {
                return processTokenFilter(request, r, next);
            }
        });
    }

    private Mono<ClientResponse> processTokenFilter(ClientRequest outboundRequest, ServerHttpRequest inboundRequest, ExchangeFunction exchangeFunction) {
        List<TokenRequestFilter.RequestFilter> requestFilterList = tokenRequestFilter.getRequestFilters();
        int index = 0;
        LOG.debug("requestFilterList.size {}, requestFilters: {}", requestFilterList.size(), requestFilterList);

        for (TokenRequestFilter.RequestFilter requestFilter : requestFilterList) {

            LOG.info("checking requestFilter[{}]  {}", index++, requestFilter);

            if (requestFilter.getInHttpMethods() != null && !requestFilter.getInHttpMethods().isEmpty()) {
                LOG.debug("httpMethods: {} provided, actual inbound request httpMethod: {}", requestFilter.getInHttpMethodSet(),
                        inboundRequest.getMethod().name());

                //very important: match the inbound request (r) path, NOT the outbound request (request)
                if (requestFilter.getInHttpMethodSet().contains(inboundRequest.getMethod().name().toLowerCase())) {
                    LOG.info("request.method {} matched with provided inbound httpMethod", inboundRequest.getMethod().name());

                    LOG.info("uri: {}, localAddress: {}", inboundRequest.getURI(), inboundRequest.getLocalAddress());
                    boolean matchInPath = requestFilter.getInSet().stream().anyMatch(w -> inboundRequest.getPath().pathWithinApplication().value().matches(w));

                    if (matchInPath) {
                        LOG.info("inPath match found, check outPath next");
                        boolean matchOutPath = requestFilter.getOutSet().stream().anyMatch(w -> {
                            boolean value = outboundRequest.url().getPath().matches(w); //use request var for outbound request
                            LOG.debug("w '{}' matches request.url.path '{}', result: {}", w, outboundRequest.url().getPath(), value);
                            return value;
                        });
                        if (matchOutPath) {
                            LOG.info("inbound and outbound path matched");
                            return passInboundTokenOrRequestOrDoNothing(requestFilter, outboundRequest, inboundRequest, exchangeFunction);
                        }
                    }

                }
            } else {
                if (requestFilter.getIn().isEmpty() && requestFilter.getOut().isEmpty()) {
                    LOG.info("user request filter to apply a overall filter when httpMethods empty, out is empty and in is empty");
                    return passInboundTokenOrRequestOrDoNothing(requestFilter, outboundRequest, inboundRequest, exchangeFunction);
                }
            }
        }

        LOG.info("httpMethods didn't even match, executing default action of pass thru");
        ClientRequest clientRequest = ClientRequest.from(outboundRequest).build();
        return exchangeFunction.exchange(clientRequest);
    }

    public Mono<ClientResponse> passInboundTokenOrRequestOrDoNothing(TokenRequestFilter.RequestFilter requestFilter, ClientRequest request,
                                                                     ServerHttpRequest serverHttpRequest, ExchangeFunction exchangeFunction) {

        LOG.debug("check if to request token, forward inbound token, or do nothing");

        if (requestFilter.getAccessToken().getOption().name().equals(TokenRequestFilter.RequestFilter.AccessToken.JwtOption.request.name())) {
            LOG.info("tokenFilter requests a client credential flow");

            if (serverHttpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION) != null &&
                    !serverHttpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION).isEmpty()) {

                return getClientRequestWithHeader(request, serverHttpRequest, exchangeFunction);
            }
            else{
                    return requestTokenAndCreateClientRequest(requestFilter, request, serverHttpRequest, exchangeFunction);
            }
        }
        else if (requestFilter.getAccessToken().getOption().name()
                .equals(TokenRequestFilter.RequestFilter.AccessToken.JwtOption.forward.name())) {

            return getClientRequestWithHeader(request, serverHttpRequest, exchangeFunction);
        }
        else {
            LOG.info("do nothing and execute");
            ClientRequest clientRequest = ClientRequest.from(request).build();
            return exchangeFunction.exchange(clientRequest);

        }
    }


    private Mono<ClientResponse> requestTokenAndCreateClientRequest(TokenRequestFilter.RequestFilter requestFilter, ClientRequest request,
                                                                    ServerHttpRequest serverHttpRequest, ExchangeFunction exchangeFunction) {
        LOG.debug("request access-token");
        return getAccessTokenCheck(requestFilter.getAccessToken()).flatMap(s -> {
            final String originHeader = serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN);
            return getClientRequestWithHeader(s, originHeader, request, exchangeFunction);
        });
    }

    private Mono<ClientResponse> getClientRequestWithHeader(ClientRequest request, ServerHttpRequest serverHttpRequest,
                                                            ExchangeFunction exchangeFunction) {

        String accessTokenHeader = serverHttpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (accessTokenHeader != null && !accessTokenHeader.isEmpty()) {
            LOG.debug("passing inbound request bearer token");

            final String inboundAccessToken = accessTokenHeader.replace("Bearer ", "");
            final String originHeader = serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN);

            return getClientRequestWithHeader(inboundAccessToken, originHeader, request, exchangeFunction);
        }
        return Mono.empty();
    }


    private Mono<ClientResponse> getClientRequestWithHeader(String accessToken, String originHeader, ClientRequest request, ExchangeFunction next) {
        ClientRequest clientRequest = createClientRequestWithHeader(accessToken, originHeader, request, next);
        return next.exchange(clientRequest);
    }

    private ClientRequest createClientRequestWithHeader(String accessToken, String originHeader, ClientRequest request, ExchangeFunction next) {
        return ClientRequest.from(request)
                .headers(headers -> {
                    if (originHeader != null) {
                        headers.set(HttpHeaders.ORIGIN, originHeader);
                        LOG.debug("set origin header");
                    }
                    if (accessToken != null) {
                        headers.setBearerAuth(accessToken);
                        LOG.debug("set authorization header with {}", accessToken);
                    }
                }).build();
    }

    private boolean isExpired(LocalDateTime tokenTime) {
        LocalDateTime tokenExpiredTime = LocalDateTime.now().minus(Duration.ofSeconds(tokenExpireSeconds));

        return tokenTime.isBefore(tokenExpiredTime);
    }

    private Mono<String> getAccessTokenCheck(TokenRequestFilter.RequestFilter.AccessToken accessToken) {
        if (accessToken.getAccessToken() != null && !isExpired(accessToken.getAccessTokenCreationTime())) {
            LOG.info("access token is not expired, return that instead");
            return Mono.just(accessToken.getAccessToken());
        }

        return generateAccessToken(accessToken);
    }

    public Mono<String> generateAccessToken(TokenRequestFilter.RequestFilter.AccessToken accessToken) {
        LOG.info("get access token using base64EncodedClientIdAndSecret: {}," +
                        " b64ClientIdAndSecret: {}, scopes: {}", oauth2TokenEndpoint,
                accessToken.getBase64EncodedClientIdSecret(),
                accessToken.getScopes());
        final StringBuilder oauthEndpointWithScope = new StringBuilder(oauth2TokenEndpoint);

        MultiValueMap<String, Object> multiValueMap = new LinkedMultiValueMap<>();
        multiValueMap.add("grant_type", grantType);

        if (accessToken.getScopes() != null && !accessToken.getScopes().trim().isEmpty()) {
            multiValueMap.add("scope", accessToken.getScopes());
            LOG.info("added scope: {}", accessToken.getScopes());
        }

        LOG.info("sending oauth2TokenEndpointWithScopes: {}", oauthEndpointWithScope);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(oauthEndpointWithScope.toString())
                .bodyValue(multiValueMap)
                .headers(httpHeaders -> httpHeaders.setBasicAuth(accessToken.getBase64EncodedClientIdSecret()))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {
        }).map(map -> {
            LOG.debug("response for '{}' is in map: {}", oauth2TokenEndpoint, map);
            if (map.get("access_token") != null) {
                accessToken.setAccessToken(map.get("access_token"));
                return map.get("access_token");
            } else {
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