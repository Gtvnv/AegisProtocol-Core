package br.com.github.gtvnv.threat.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
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
    private final AuditEventPublisher chainPublisher;

    private static final int MAX_ATTEMPTS = 5;
    private static final int BLOCK_DURATION_MINUTES = 15;
    private static final String COUNTER_PREFIX = "threat:login_attempt:";
    private static final String BLOCKED_PREFIX  = "threat:blocked:";

    /**
     * Verifica e incrementa tentativas de login por IP de forma atômica.
     *
     * Estratégia de dois estágios:
     *  1. BLOCKED key — fast-fail sem tocar no contador.
     *  2. COUNTER key — INCR atômico; ao cruzar MAX_ATTEMPTS seta BLOCKED key.
     *
     * O INCR do Redis é atômico, eliminando o race condition do MVP anterior
     * (GET → check → INCR separados não eram thread-safe sob carga concorrente).
     */
    public void checkLoginAttempts(String ipAddress) {
        // Fast-fail: IP já está explicitamente bloqueado
        if (Boolean.TRUE.equals(redisTemplate.hasKey(BLOCKED_PREFIX + ipAddress))) {
            log.warn("SHIELD: IP {} tentou acesso enquanto bloqueado.", ipAddress);
            chainPublisher.publishThreatEvent(AuditEventType.IP_BLOCKED_EXPLICIT,
                    ipAddress, ipAddress, null, 0);
            throw new RateLimitException("Too many attempts. Blocked for 15 minutes.");
        }

        String counterKey = COUNTER_PREFIX + ipAddress;
        Long count = redisTemplate.opsForValue().increment(counterKey);

        // Na primeira tentativa, define o TTL da janela de contagem
        if (count != null && count == 1L) {
            redisTemplate.expire(counterKey, Duration.ofMinutes(BLOCK_DURATION_MINUTES));
        }

        if (count != null && count > MAX_ATTEMPTS) {
            // Cria chave de bloqueio explícita para fast-fail nas próximas requisições
            redisTemplate.opsForValue().set(
                    BLOCKED_PREFIX + ipAddress, "1",
                    Duration.ofMinutes(BLOCK_DURATION_MINUTES)
            );
            log.warn("THREAT DETECTED: IP {} bloqueado após {} tentativas.", ipAddress, count);
            chainPublisher.publishThreatEvent(AuditEventType.IP_RATE_LIMIT_EXCEEDED,
                    ipAddress, ipAddress, null, count.intValue());
            throw new RateLimitException("Too many attempts. Blocked for 15 minutes.");
        }
    }

    public void clearLoginAttempts(String ipAddress) {
        redisTemplate.delete(COUNTER_PREFIX + ipAddress);
        redisTemplate.delete(BLOCKED_PREFIX + ipAddress);
    }
}
