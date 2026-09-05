package br.com.github.gtvnv.audit.chain.listener;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.event.ChainAuditEvent;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testa o ChainAuditListener:
 * 1. Delegação correta ao AuditChainService com todos os campos do evento
 * 2. Exceção no service NÃO propaga — listener é não-bloqueante por design
 */
@ExtendWith(MockitoExtension.class)
class ChainAuditListenerTest {

    @Mock  private AuditChainService chainService;
    @InjectMocks private ChainAuditListener listener;

    private ChainAuditEvent buildEvent(AuditEventType type, String actor) {
        return new ChainAuditEvent(
            this, type, actor, "jti-test",
            "127.0.0.1", "Mozilla/5.0", "/api/secret",
            "test detail", Map.of("key", "value")
        );
    }

    // -----------------------------------------------------------------------
    // Delegação ao service
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("onChainAuditEvent delega ao AuditChainService com todos os campos do evento")
    void onChainAuditEvent_DelegatesToServiceWithAllFields() {
        ChainAuditEvent event = buildEvent(AuditEventType.LOGIN_SUCCESS, "alice");

        listener.onChainAuditEvent(event);

        verify(chainService).append(
            eq(AuditEventType.LOGIN_SUCCESS),
            eq("alice"),
            eq("jti-test"),
            eq("127.0.0.1"),
            eq("Mozilla/5.0"),
            eq("/api/secret"),
            eq("test detail"),
            argThat(p -> p.containsKey("key") && p.get("key").equals("value"))
        );
    }

    @Test
    @DisplayName("Actor null no evento é normalizado para 'ANONYMOUS' pelo ChainAuditEvent")
    void onChainAuditEvent_NullActor_DelegatesWithAnonymous() {
        ChainAuditEvent event = buildEvent(AuditEventType.TOKEN_BLACKLIST_VIOLATION, null);

        listener.onChainAuditEvent(event);

        verify(chainService).append(
            any(), eq("ANONYMOUS"), any(), any(), any(), any(), any(), any()
        );
    }

    // -----------------------------------------------------------------------
    // Tolerância a falhas (não-bloqueante)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Exceção no AuditChainService NÃO propaga para o chamador — listener é fire-and-forget")
    void onChainAuditEvent_ServiceThrows_ExceptionDoesNotPropagate() {
        ChainAuditEvent event = buildEvent(AuditEventType.IP_BLOCKED_EXPLICIT, "attacker");
        doThrow(new RuntimeException("DB failure"))
            .when(chainService).append(any(), any(), any(), any(), any(), any(), any(), any());

        assertThatCode(() -> listener.onChainAuditEvent(event))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("RuntimeException aleatória no service não bloqueia fluxo principal")
    void onChainAuditEvent_UnexpectedServiceError_DoesNotBlowUp() {
        ChainAuditEvent event = buildEvent(AuditEventType.SHIELD_REQUEST_BLOCKED, "suspect");
        doThrow(new IllegalStateException("Chain corrupted"))
            .when(chainService).append(any(), any(), any(), any(), any(), any(), any(), any());

        assertThatCode(() -> listener.onChainAuditEvent(event))
            .doesNotThrowAnyException();
    }

    // -----------------------------------------------------------------------
    // Todos os AuditEventTypes são processados
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("LOGIN_FAILURE é encaminhado corretamente ao service")
    void onChainAuditEvent_LoginFailure_Delegated() {
        ChainAuditEvent event = buildEvent(AuditEventType.LOGIN_FAILURE, "hacker");
        listener.onChainAuditEvent(event);
        verify(chainService).append(eq(AuditEventType.LOGIN_FAILURE), eq("hacker"),
            any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("ABAC_DECISION_DENY é encaminhado corretamente ao service")
    void onChainAuditEvent_AbacDeny_Delegated() {
        ChainAuditEvent event = buildEvent(AuditEventType.ABAC_DECISION_DENY, "user");
        listener.onChainAuditEvent(event);
        verify(chainService).append(eq(AuditEventType.ABAC_DECISION_DENY), any(),
            any(), any(), any(), any(), any(), any());
    }
}
