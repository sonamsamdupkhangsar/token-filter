package me.sonam.security.headerfilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.client.WebClient;

@Profile("localdevtest")
@Configuration
public class JwtHeaderWebClientTestConfig {
    private static final Logger LOG = LoggerFactory.getLogger(JwtHeaderWebClientTestConfig.class);
    @Bean("loadBalancedWebClient")
    public WebClient.Builder webClientBuilder() {
        LOG.info("returning jwt-validator non-loadBalanced webClient for testing profile only");
        return WebClient.builder();
    }
}
