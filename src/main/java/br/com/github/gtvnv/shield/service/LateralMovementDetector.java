package br.com.github.gtvnv.shield.service;

import br.com.github.gtvnv.shield.config.ShieldProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Detecta movimentação lateral: um único token JWT (JTI) acessando um número
 * anômalo de recursos distintos em uma janela de tempo curta.
 *
 * Chave Redis:
 *   shield:session:{jti}:resources → Set de resource paths (TTL = sessionWindowMinutes)
 */
@Service
@RequiredArgsConstructor
public class LateralMovementDetector {

    private final StringRedisTemplate redisTemplate;
    private final ShieldProperties props;

    private static final String SESSION_RESOURCES_PREFIX = "shield:session:%s:resources";

    /**
     * Registra o acesso ao resource e retorna true se movimento lateral for detectado.
     */
    public boolean recordAndDetect(String jti, String resourcePath) {
        String key = SESSION_RESOURCES_PREFIX.formatted(jti);
        Duration window = Duration.ofMinutes(props.getSessionWindowMinutes());

        redisTemplate.opsForSet().add(key, resourcePath);
        redisTemplate.expire(key, window);

        Long distinctCount = redisTemplate.opsForSet().size(key);
        return distinctCount != null && distinctCount >= props.getLateralMovementResourceLimit();
    }

    public long getDistinctResourceCount(String jti) {
        Long size = redisTemplate.opsForSet().size(SESSION_RESOURCES_PREFIX.formatted(jti));
        return size != null ? size : 0L;
    }
}
