package br.com.github.gtvnv.audit.chain.listener;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.event.ChainAuditEvent;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import br.com.github.gtvnv.privacy.service.PrivacyGateService;
import org.junit.jupiter.api.BeforeEach;
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
 * 3. PrivacyGate: actor pseudonimizado para categorias de identidade, passa
 *    direto para THREAT (IP) e para ANONYMOUS
 */
@ExtendWith(MockitoExtension.class)
class ChainAuditListenerTest {

    @Mock  private AuditChainService chainService;
    @Mock  private PrivacyGateService privacyGate;
    @InjectMocks private ChainAuditListener listener;

    @BeforeEach
    void setUp() {
        lenient().when(privacyGate.pseudonymize(anyString()))
            .thenAnswer(inv -> "pseudo_" + inv.getArgument(0));
    }

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
            eq("pseudo_alice"), // PrivacyGate: actor gravado é o pseudônimo, não "alice"
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
        verify(chainService).append(eq(AuditEventType.LOGIN_FAILURE), eq("pseudo_hacker"),
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

    // -----------------------------------------------------------------------
    // PrivacyGate
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("PrivacyGate: eventos THREAT passam com o IP intacto — não são pseudonimizados")
    void onChainAuditEvent_ThreatCategory_ActorPassesThroughRaw() {
        ChainAuditEvent event = new ChainAuditEvent(
            this, AuditEventType.IP_RATE_LIMIT_EXCEEDED, "10.0.0.9", null,
            "10.0.0.9", null, null, "too many attempts",
            Map.of("eventCategory", "THREAT")
        );

        listener.onChainAuditEvent(event);

        verify(chainService).append(any(), eq("10.0.0.9"), any(), any(), any(), any(), any(), any());
        verify(privacyGate, never()).pseudonymize(any());
    }

    @Test
    @DisplayName("PrivacyGate: categoria desconhecida ainda é pseudonimizada — fail-safe a favor da privacidade")
    void onChainAuditEvent_UnknownCategory_StillPseudonymized() {
        ChainAuditEvent event = new ChainAuditEvent(
            this, AuditEventType.SIGNING_KEY_ROTATED, "admin", null,
            "127.0.0.1", null, null, "rotated",
            Map.of("eventCategory", "KMS")
        );

        listener.onChainAuditEvent(event);

        verify(chainService).append(any(), eq("pseudo_admin"), any(), any(), any(), any(), any(), any());
    }
}
