package br.com.github.gtvnv.authentication.revocation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService implements TokenRevocationManager{

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "blacklist:token:";

    /**
     * Adiciona o token na lista negra.
     * @param token O token JWT (apenas a string, sem 'Bearer')
     * @param ttlSeconds O tempo que falta para o token expirar (em segundos)
     */
    public void blacklistToken(String token, long ttlSeconds) {
        String key = PREFIX + token;
        redisTemplate.opsForValue().set(key, "revoked", Duration.ofSeconds(ttlSeconds));
    }

    /**
     * public boolean isTokenBlacklisted(String token) {
     *         String key = PREFIX + token;
     *         return Boolean.TRUE.equals(redisTemplate.hasKey(key));
     *     }
     */
    public boolean isTokenBlacklisted(String token) {
        String key = PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    @Override
    public void revoke(String token, long ttlSeconds) {

    }

    @Override
    public boolean isRevoked(String token) {
        return false;
    }
}