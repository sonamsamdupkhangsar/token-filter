package me.sonam.security.headerfilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class JwtHeaderWebClientConfig {
    private static final Logger LOG = LoggerFactory.getLogger(JwtHeaderWebClientConfig.class);
    @LoadBalanced
    @Bean("loadBalancedWebClient")
    public WebClient.Builder webClientBuilder() {
        LOG.info("returning jwt-validator loadBalancedWebClient");
        return WebClient.builder();
    }
}
