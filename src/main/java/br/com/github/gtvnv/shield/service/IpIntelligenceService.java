package br.com.github.gtvnv.shield.service;

import br.com.github.gtvnv.shield.config.ShieldProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Rastreia comportamento de IPs no Redis.
 *
 * Chaves Redis:
 *   shield:ip:{ip}:resources  → Set de resource paths acessados pelo IP na janela de tempo
 *   shield:ip:{ip}:req_count  → Contador de requisições do IP na janela
 */
@Service
@RequiredArgsConstructor
public class IpIntelligenceService {

    private final StringRedisTemplate redisTemplate;
    private final ShieldProperties props;

    private static final String IP_RESOURCES_PREFIX  = "shield:ip:%s:resources";
    private static final String IP_REQ_COUNT_PREFIX  = "shield:ip:%s:req_count";

    public void recordAccess(String ipAddress, String resourcePath) {
        Duration window = Duration.ofMinutes(props.getSessionWindowMinutes());

        String resourcesKey = IP_RESOURCES_PREFIX.formatted(ipAddress);
        String reqCountKey  = IP_REQ_COUNT_PREFIX.formatted(ipAddress);

        redisTemplate.opsForSet().add(resourcesKey, resourcePath);
        redisTemplate.expire(resourcesKey, window);

        Long count = redisTemplate.opsForValue().increment(reqCountKey);
        if (count != null && count == 1L) {
            redisTemplate.expire(reqCountKey, window);
        }
    }

    /** Número de recursos distintos que esse IP acessou na janela atual. */
    public long getDistinctResourceCount(String ipAddress) {
        Long size = redisTemplate.opsForSet().size(IP_RESOURCES_PREFIX.formatted(ipAddress));
        return size != null ? size : 0L;
    }

    /** Total de requisições do IP na janela atual. */
    public long getRequestCount(String ipAddress) {
        String val = redisTemplate.opsForValue().get(IP_REQ_COUNT_PREFIX.formatted(ipAddress));
        return val != null ? Long.parseLong(val) : 0L;
    }
}
