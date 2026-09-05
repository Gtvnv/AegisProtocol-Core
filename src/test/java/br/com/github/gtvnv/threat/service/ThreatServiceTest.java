package br.com.github.gtvnv.threat.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.threat.exception.RateLimitException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes adversariais do ThreatService (rate-limiting por IP).
 *
 * Cobre: fast-fail de IP bloqueado, janela de contagem, limiar exato (5),
 * bloqueio ao cruzar (6), publicação de eventos de auditoria,
 * TTL aplicado só na primeira tentativa, clearLoginAttempts.
 */
@ExtendWith(MockitoExtension.class)
class ThreatServiceTest {

    @Mock private StringRedisTemplate    redisTemplate;
    @Mock private AuditEventPublisher    chainPublisher;
    @Mock private ValueOperations<String, String> valueOps;

    @InjectMocks
    private ThreatService threatService;

    private static final String IP          = "192.168.1.100";
    private static final String BLOCKED_KEY = "threat:blocked:" + IP;
    private static final String COUNTER_KEY = "threat:login_attempt:" + IP;

    @BeforeEach
    void setup() {
        // Padrão: IP NÃO está na lista de bloqueados
        lenient().when(redisTemplate.hasKey(BLOCKED_KEY)).thenReturn(false);
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOps);
    }

    // -----------------------------------------------------------------------
    // Tentativas dentro do limite (1–5)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Primeira tentativa (count=1): sem exceção, TTL da janela é definido")
    void checkLoginAttempts_FirstAttempt_PassesAndSetsTtl() {
        when(valueOps.increment(COUNTER_KEY)).thenReturn(1L);
        when(redisTemplate.expire(eq(COUNTER_KEY), any(Duration.class))).thenReturn(true);

        assertThatCode(() -> threatService.checkLoginAttempts(IP))
            .doesNotThrowAnyException();

        verify(redisTemplate).expire(eq(COUNTER_KEY), any(Duration.class));
    }

    @Test
    @DisplayName("Tentativas 2–4 (count < 5): sem exceção, TTL NÃO é redefinido")
    void checkLoginAttempts_MiddleAttempts_PassWithoutResettingTtl() {
        for (long count = 2L; count <= 4L; count++) {
            when(valueOps.increment(COUNTER_KEY)).thenReturn(count);

            assertThatCode(() -> threatService.checkLoginAttempts(IP))
                .doesNotThrowAnyException();
        }

        // expire só é chamado quando count == 1 — não deve ser chamado aqui
        verify(redisTemplate, never()).expire(eq(COUNTER_KEY), any(Duration.class));
    }

    @Test
    @DisplayName("Quinta tentativa (count=5, exatamente no limite): ainda passa")
    void checkLoginAttempts_FifthAttempt_StillPasses() {
        when(valueOps.increment(COUNTER_KEY)).thenReturn(5L);

        assertThatCode(() -> threatService.checkLoginAttempts(IP))
            .doesNotThrowAnyException();

        verify(chainPublisher, never()).publishThreatEvent(any(), any(), any(), any(), anyInt());
    }

    // -----------------------------------------------------------------------
    // Cruzar o limite (> 5)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sexta tentativa (count=6): lança RateLimitException e publica IP_RATE_LIMIT_EXCEEDED")
    void checkLoginAttempts_SixthAttempt_ThrowsAndPublishesRateLimitEvent() {
        when(valueOps.increment(COUNTER_KEY)).thenReturn(6L);

        assertThatThrownBy(() -> threatService.checkLoginAttempts(IP))
            .isInstanceOf(RateLimitException.class)
            .hasMessageContaining("Too many attempts");

        verify(chainPublisher).publishThreatEvent(
            eq(AuditEventType.IP_RATE_LIMIT_EXCEEDED),
            eq(IP), eq(IP), isNull(), eq(6));
    }

    @Test
    @DisplayName("Décima tentativa (count=10): ainda lança e cria chave de bloqueio")
    void checkLoginAttempts_TenthAttempt_ThrowsAndCreatesBlockedKey() {
        when(valueOps.increment(COUNTER_KEY)).thenReturn(10L);

        assertThatThrownBy(() -> threatService.checkLoginAttempts(IP))
            .isInstanceOf(RateLimitException.class);

        verify(valueOps).set(eq(BLOCKED_KEY), eq("1"), any(Duration.class));
    }

    // -----------------------------------------------------------------------
    // Fast-fail: IP já bloqueado
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("IP já bloqueado: fast-fail, lança RateLimitException antes de incrementar contador")
    void checkLoginAttempts_AlreadyBlocked_FastFailsWithoutIncrementingCounter() {
        when(redisTemplate.hasKey(BLOCKED_KEY)).thenReturn(true);

        assertThatThrownBy(() -> threatService.checkLoginAttempts(IP))
            .isInstanceOf(RateLimitException.class)
            .hasMessageContaining("Too many attempts");

        // CRITICAL: contador nunca é incrementado quando IP está bloqueado
        verify(redisTemplate, never()).opsForValue();
        verify(valueOps, never()).increment(any());
    }

    @Test
    @DisplayName("IP bloqueado: publica IP_BLOCKED_EXPLICIT com score=0")
    void checkLoginAttempts_AlreadyBlocked_PublishesBlockedExplicitEvent() {
        when(redisTemplate.hasKey(BLOCKED_KEY)).thenReturn(true);

        try { threatService.checkLoginAttempts(IP); } catch (RateLimitException ignored) {}

        verify(chainPublisher).publishThreatEvent(
            eq(AuditEventType.IP_BLOCKED_EXPLICIT),
            eq(IP), eq(IP), isNull(), eq(0));
    }

    @Test
    @DisplayName("IP bloqueado: evento IP_RATE_LIMIT_EXCEEDED NÃO é publicado no fast-fail")
    void checkLoginAttempts_AlreadyBlocked_DoesNotPublishRateLimitEvent() {
        when(redisTemplate.hasKey(BLOCKED_KEY)).thenReturn(true);

        try { threatService.checkLoginAttempts(IP); } catch (RateLimitException ignored) {}

        verify(chainPublisher, never()).publishThreatEvent(
            eq(AuditEventType.IP_RATE_LIMIT_EXCEEDED), any(), any(), any(), anyInt());
    }

    // -----------------------------------------------------------------------
    // TTL: definido apenas na primeira tentativa
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("TTL da janela de contagem só é definido quando count == 1")
    void checkLoginAttempts_TtlIsOnlySetOnFirstIncrement() {
        when(valueOps.increment(COUNTER_KEY)).thenReturn(3L); // terceira tentativa

        assertThatCode(() -> threatService.checkLoginAttempts(IP))
            .doesNotThrowAnyException();

        // expire NÃO deve ser chamado para count > 1
        verify(redisTemplate, never()).expire(eq(COUNTER_KEY), any(Duration.class));
    }

    @Test
    @DisplayName("TTL da chave de bloqueio é de 15 minutos")
    void checkLoginAttempts_BlockedKeyTtl_IsFifteenMinutes() {
        when(valueOps.increment(COUNTER_KEY)).thenReturn(6L);

        try { threatService.checkLoginAttempts(IP); } catch (RateLimitException ignored) {}

        verify(valueOps).set(eq(BLOCKED_KEY), eq("1"),
            eq(Duration.ofMinutes(15)));
    }

    // -----------------------------------------------------------------------
    // clearLoginAttempts
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("clearLoginAttempts remove chave de contador E chave de bloqueio")
    void clearLoginAttempts_DeletesBothKeys() {
        threatService.clearLoginAttempts(IP);

        verify(redisTemplate).delete(COUNTER_KEY);
        verify(redisTemplate).delete(BLOCKED_KEY);
    }

    @Test
    @DisplayName("clearLoginAttempts é idempotente — chamadas repetidas não lançam exceção")
    void clearLoginAttempts_IsIdempotent() {
        assertThatCode(() -> {
            threatService.clearLoginAttempts(IP);
            threatService.clearLoginAttempts(IP);
        }).doesNotThrowAnyException();
    }

    // -----------------------------------------------------------------------
    // IPs diferentes são independentes
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Bloqueio de um IP não afeta outro IP")
    void checkLoginAttempts_DifferentIPs_AreIndependent() {
        String otherIp   = "10.0.0.99";
        String otherBlocked  = "threat:blocked:" + otherIp;
        String otherCounter  = "threat:login_attempt:" + otherIp;

        // IP original bloqueado, outro IP não
        when(redisTemplate.hasKey(BLOCKED_KEY)).thenReturn(true);
        when(redisTemplate.hasKey(otherBlocked)).thenReturn(false);
        when(valueOps.increment(otherCounter)).thenReturn(1L);
        when(redisTemplate.expire(eq(otherCounter), any())).thenReturn(true);

        // IP bloqueado falha
        assertThatThrownBy(() -> threatService.checkLoginAttempts(IP))
            .isInstanceOf(RateLimitException.class);

        // Outro IP passa normalmente
        assertThatCode(() -> threatService.checkLoginAttempts(otherIp))
            .doesNotThrowAnyException();
    }
}
