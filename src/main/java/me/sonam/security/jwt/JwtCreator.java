package me.sonam.security.jwt;

import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

public interface JwtCreator {
    Mono<String> create(String clientId, String groupNames, String subject, String audience, int calendarField, int calendarValue);
}
