package me.sonam.security.headerfilter;

import me.sonam.security.SecurityException;
import me.sonam.security.util.TokenRequestFilter;
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

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;


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
    private TokenRequestFilter tokenRequestFilter;

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
                    return serverHttpRequest;
                });
    }

    public ExchangeFilterFunction headerFilter() {
        LOG.info("in headerFilter()");
        return (request, next) -> ReactiveRequestContextHolder.getRequest().flatMap(r ->
                {
                    LOG.info("inbound path: {}, outbound path: {}", r.getPath().pathWithinApplication().value(),
                            request.url().getPath());

                    if (request.url().getPath().equals(accessTokenPath)) {
                        LOG.debug("don't call itself if using the same webclient builder");
                        ClientRequest clientRequest = ClientRequest.from(request).build();
                        return next.exchange(clientRequest);
                    }
                    else {
                        List<TokenRequestFilter.RequestFilter> requestFilterList = tokenRequestFilter.getRequestFilters();
                        int index = 0;
                        for (TokenRequestFilter.RequestFilter requestFilter : requestFilterList) {
                            LOG.info("checking requestFilter[{}]  {}", index++, requestFilter);

                            if (requestFilter.getHttpMethods() != null) {
                                LOG.debug("httpMethods: {} provided, actual requeset httpMethod: {}", requestFilter.getHttpMethodSet(),
                                        r.getMethod().name());

                                if (requestFilter.getHttpMethodSet().contains(r.getMethod().name().toLowerCase())) {
                                    LOG.info("request.method {} matched with provided httpMethod", r.getMethod().name());

                                    boolean matchInPath = requestFilter.getInSet().stream().anyMatch(w -> r.getPath().pathWithinApplication().value().matches(w));

                                    if (matchInPath) {
                                        LOG.info("inPath match found, check outPath next");
                                        boolean matchOutPath = requestFilter.getOutSet().stream().anyMatch(w -> {
                                            boolean value = request.url().getPath().matches(w);
                                            LOG.debug("w '{}' matches request.url.path '{}', result: {}", w, request.url().getPath(), value);
                                            return value;
                                        });
                                        if (matchOutPath) {
                                            LOG.info("inbound and outbound path matched");
                                            return getClientResponse(requestFilter, request, r, next);
                                        }
                                        else {
                                            LOG.info("no match found for outbound path {} ",
                                                    request.url().getPath());
                                        }
                                    }
                                    else {
                                        LOG.info("no match found for inbound path {}",
                                                r.getPath().pathWithinApplication().value());
                                    }
                                }
                            }
                        }

                        LOG.info("httpMethods didn't even match, executing default action of pass thru");
                        ClientRequest clientRequest = ClientRequest.from(request).build();
                        return next.exchange(clientRequest);
                    }

                });

    }

    private Mono<ClientResponse> getClientResponse(TokenRequestFilter.RequestFilter requestFilter, ClientRequest request,
                                                   ServerHttpRequest serverHttpRequest, ExchangeFunction exchangeFunction) {
            if (requestFilter.getAccessToken().getOption().name().equals(TokenRequestFilter.RequestFilter.AccessToken.JwtOption.request.name())) {
                return getAccessToken(requestFilter.getAccessToken()).flatMap(s -> {
                    ClientRequest clientRequest = ClientRequest.from(request)
                            .headers(headers -> {
                                headers.set(HttpHeaders.ORIGIN, serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN));
                                headers.setBearerAuth(s);
                                LOG.info("added jwt to header from access token http callout");
                            }).build();
                    return exchangeFunction.exchange(clientRequest);
                });
            }
            else if (requestFilter.getAccessToken().getOption().name()
                    .equals(TokenRequestFilter.RequestFilter.AccessToken.JwtOption.forward.name())) {

                ClientRequest clientRequest = ClientRequest.from(request)
                        .headers(headers -> {
                            String accessTokenHeader = serverHttpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                            LOG.info("accessTokenHeader: {}", accessTokenHeader);
                            if (accessTokenHeader != null && accessTokenHeader.contains("Bearer ")) {
                                final String accessToken = accessTokenHeader.replace("Bearer ", "");

                                headers.set(HttpHeaders.ORIGIN, serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN));
                                headers.set(HttpHeaders.AUTHORIZATION,  accessToken);
                                LOG.info("pass inbound accessToken : {}", accessToken);
                            }
                            else {
                                LOG.error("inbound request does not contain valid accessToken is {}", accessTokenHeader);
                            }

                        }).build();
                return exchangeFunction.exchange(clientRequest);
            }
            else {
                LOG.info("don't pass headers to downstream web service");
                ClientRequest clientRequest = ClientRequest.from(request).build();
                return exchangeFunction.exchange(clientRequest);
            }
    }

    private Mono<String> getAccessToken(TokenRequestFilter.RequestFilter.AccessToken accessToken) {
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