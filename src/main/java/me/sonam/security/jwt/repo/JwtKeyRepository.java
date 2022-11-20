package me.sonam.security.jwt.repo;

import me.sonam.security.jwt.repo.entity.JwtKey;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface JwtKeyRepository extends ReactiveCrudRepository<JwtKey, UUID> {
    @Query("update Jwt_Key jk set jk.revoked= :revoked where jk.id= :id")
    Mono<Integer> revokeKey(@Param("revoked")Boolean revoked, @Param("id")UUID id);
    Mono<JwtKey> findTop1ByRevokedIsFalse();
}
