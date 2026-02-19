package br.com.github.gtvnv.threat.service;

import br.com.github.gtvnv.threat.exception.RateLimitException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatService {

    private final StringRedisTemplate redisTemplate;

    private static final int MAX_ATTEMPTS = 5; // 5 tentativas
    private static final int BLOCK_DURATION_MINUTES = 15; // Bloqueio de 15 min
    private static final String PREFIX = "threat:login_attempt:";

    /**
     * Verifica e incrementa tentativas de login por IP.
     * @throws RuntimeException se o IP estiver bloqueado.
     */
    public void checkLoginAttempts(String ipAddress) {
        String key = PREFIX + ipAddress;

        String currentCountStr = redisTemplate.opsForValue().get(key);
        int currentCount = currentCountStr != null ? Integer.parseInt(currentCountStr) : 0;

        if (currentCount >= MAX_ATTEMPTS) {
            log.warn("🚨 THREAT DETECTED: IP {} blocked.", ipAddress);
            // Troque RuntimeException por RateLimitException
            throw new RateLimitException("Too many attempts. Blocked for 15 minutes.");
        }

        // Incrementa o contador
        redisTemplate.opsForValue().increment(key);

        // Se for a primeira tentativa, define a expiração da chave para limpar o histórico
        if (currentCount == 0) {
            redisTemplate.opsForValue().getAndExpire(key, Duration.ofMinutes(BLOCK_DURATION_MINUTES));
        }
    }

    public void clearLoginAttempts(String ipAddress) {
        redisTemplate.delete(PREFIX + ipAddress);
    }
}