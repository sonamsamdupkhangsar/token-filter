package me.sonam.security.headerfilter;

import me.sonam.security.SecurityException;
import me.sonam.security.util.HmacClient;
import me.sonam.security.util.JwtPath;
import me.sonam.security.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.*;
import org.springframework.web.reactive.function.server.ServerRequest;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

@Service
public class ReactiveRequestContextHolder {
    private static final Logger LOG = LoggerFactory.getLogger(ReactiveRequestContextHolder.class);
    static final Class<ServerHttpRequest> CONTEXT_KEY = ServerHttpRequest.class;

    @Value("${jwt-rest-service-accesstoken}")
    private String jwtRestServiceAccessToken;

    @Autowired
    private JwtPath jwtPath;

    @Autowired
    private HmacClient hmacClient;

    private WebClient webClient;

    @PostConstruct
    public void setWebClient() {
        webClient = WebClient.builder().build();
    }

    public static Mono<ServerHttpRequest> getRequest() {
        return Mono.subscriberContext()
                .map(ctx -> ctx.get(CONTEXT_KEY)).map(serverHttpRequest -> {
                    LOG.info("serverHttpRequest: {}", serverHttpRequest.getPath());
                    return serverHttpRequest;
                });
    }

    public ExchangeFilterFunction headerFilter() {
        LOG.info("calling new headerFilter");
        return (request, next) -> ReactiveRequestContextHolder.getRequest().flatMap(r ->
                {
                LOG.info("in path: {}, outbound path: {}",r.getPath().pathWithinApplication().value(),
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
                });

    }

    private Mono<ClientResponse> getClientResponse(JwtPath.JwtRequest jwtRequest, ClientRequest request,
                                                   ServerHttpRequest serverHttpRequest, ExchangeFunction exchangeFunction) {
            if (jwtRequest.getJwt().equals(JwtPath.JwtRequest.JwtOption.request.name())) {
                return getJwt().flatMap(s -> {
                    ClientRequest clientRequest = ClientRequest.from(request)
                            .headers(headers -> {
                                headers.set(HttpHeaders.ORIGIN, serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN));
                                headers.set(HttpHeaders.AUTHORIZATION, s);
                                LOG.info("added jwt to header from access token http callout");
                            }).build();
                    return exchangeFunction.exchange(clientRequest);
                });
            }
            else if (jwtRequest.getJwt().equals(JwtPath.JwtRequest.JwtOption.forward.name())) {
                ClientRequest clientRequest = ClientRequest.from(request)
                        .headers(headers -> {
                            headers.set(HttpHeaders.ORIGIN, serverHttpRequest.getHeaders().getFirst(HttpHeaders.ORIGIN));
                            headers.set(HttpHeaders.AUTHORIZATION,  serverHttpRequest.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
                            LOG.info("added jwt to header from access token http callout");
                        }).build();
                return exchangeFunction.exchange(clientRequest);
            }
            else {
                LOG.info("don't pass headers to downstream web service");
                ClientRequest clientRequest = ClientRequest.from(request).build();
                return exchangeFunction.exchange(clientRequest);
            }
    }

    private Mono<String> getJwt() {
        final String jsonString = "{\n" +
                "  \"sub\": \""+hmacClient.getClientId()+"\",\n" +
                "  \"scope\": \""+hmacClient.getClientId()+"\",\n" +
                "  \"clientId\": \""+hmacClient.getClientId()+"\",\n" +
                "  \"aud\": \"service\",\n" +
                "  \"role\": \"service\",\n" +
                "  \"groups\": \"service\",\n" +
                "  \"expiresInSeconds\": 300\n" +
                "}\n";

        final String hmac = Util.getHmac(hmacClient.getMd5Algoirthm(), jsonString, hmacClient.getSecretKey());
        LOG.info("creating hmac for jwt-rest-service: {}", jwtRestServiceAccessToken);
        WebClient.ResponseSpec responseSpec = webClient.post().uri(jwtRestServiceAccessToken)
                .headers(httpHeaders -> httpHeaders.add(HttpHeaders.AUTHORIZATION, hmac))
                .bodyValue(jsonString)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.debug("response for '{}' is in map: {}",jwtRestServiceAccessToken, map);
            if (map.get("token") != null) {
                return map.get("token").toString();
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