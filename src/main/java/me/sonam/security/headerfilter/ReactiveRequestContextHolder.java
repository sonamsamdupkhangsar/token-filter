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
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
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

        return (request, next) -> ReactiveRequestContextHolder.getRequest().flatMap(r ->
        {
            List<JwtPath.JwtRequest> jwtRequestList = jwtPath.getJwtRequest();
            for (JwtPath.JwtRequest jwtRequest : jwtRequestList) {
                if (jwtRequest.getIn().equals(r.getPath().pathWithinApplication().value()) && jwtRequest.getOut().equals(request.url().getPath())) {
                    LOG.info("inbound request path and outbound request path both matched");
                    return Mono.just(jwtRequest).zipWith(Mono.just(r));
                }
            }
            LOG.info("no path match found");
            return Mono.just(new JwtPath.JwtRequest()).zipWith(Mono.just(r));
            })
                .flatMap(objects -> {
            if (objects.getT1().getIn() != null) {
                JwtPath.JwtRequest jwtRequest =  objects.getT1();
                if (jwtRequest.getJwt().equals(JwtPath.JwtRequest.JwtOption.request.name())) {
                    return getJwt().flatMap(s -> {
                        ClientRequest clientRequest = ClientRequest.from(request)
                                .headers(headers -> {
                                    headers.set(HttpHeaders.ORIGIN, objects.getT2().getHeaders().getFirst(HttpHeaders.ORIGIN));
                                    headers.set(HttpHeaders.AUTHORIZATION, s);
                                    LOG.info("added jwt to header from access token http callout");
                                }).build();
                        return next.exchange(clientRequest);
                    });
                }
                else {
                        ClientRequest clientRequest = ClientRequest.from(request)
                                .headers(headers -> {
                                    headers.set(HttpHeaders.ORIGIN, objects.getT2().getHeaders().getFirst(HttpHeaders.ORIGIN));
                                    headers.set(HttpHeaders.AUTHORIZATION,  objects.getT2().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
                                    LOG.info("added jwt to header from access token http callout");
                                }).build();
                        return next.exchange(clientRequest);
                    }
            }
            else {
                LOG.info("just do nothing to add to header");
                ClientRequest clientRequest = ClientRequest.from(request).build();
                return next.exchange(clientRequest);
            }
        });
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