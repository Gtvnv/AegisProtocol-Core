package br.com.github.gtvnv.shield.service;

import br.com.github.gtvnv.shield.config.ShieldProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Valida a consistência da sessão JWT por IP e User-Agent.
 *
 * Na primeira requisição de um JTI, registra o "fingerprint" da sessão.
 * Nas requisições seguintes, compara — divergências incrementam o risk score.
 *
 * Chaves Redis:
 *   shield:session:{jti}:ips     → Set de IPs que usaram este JTI
 *   shield:session:{jti}:agents  → Set de User-Agents que usaram este JTI
 */
@Service
@RequiredArgsConstructor
public class SessionFingerprintService {

    private final StringRedisTemplate redisTemplate;
    private final ShieldProperties props;

    private static final String SESSION_IPS_PREFIX    = "shield:session:%s:ips";
    private static final String SESSION_AGENTS_PREFIX = "shield:session:%s:agents";

    public void record(String jti, String ipAddress, String userAgent) {
        Duration window = Duration.ofMinutes(props.getSessionWindowMinutes());
        String safeAgent = userAgent != null ? userAgent : "unknown";

        String ipsKey    = SESSION_IPS_PREFIX.formatted(jti);
        String agentsKey = SESSION_AGENTS_PREFIX.formatted(jti);

        redisTemplate.opsForSet().add(ipsKey, ipAddress);
        redisTemplate.expire(ipsKey, window);

        redisTemplate.opsForSet().add(agentsKey, safeAgent);
        redisTemplate.expire(agentsKey, window);
    }

    /** Quantos IPs distintos usaram este JTI. Valor normal = 1. */
    public long getDistinctIpCount(String jti) {
        Long size = redisTemplate.opsForSet().size(SESSION_IPS_PREFIX.formatted(jti));
        return size != null ? size : 0L;
    }

    /** Quantos User-Agents distintos usaram este JTI. Valor normal = 1. */
    public long getDistinctAgentCount(String jti) {
        Long size = redisTemplate.opsForSet().size(SESSION_AGENTS_PREFIX.formatted(jti));
        return size != null ? size : 0L;
    }
}
