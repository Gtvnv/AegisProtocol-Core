package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.event.ChainAuditEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

/**
 * Testa a fachada AuditEventPublisher:
 * cada método semântico deve publicar o ChainAuditEvent correto,
 * com todos os campos esperados e defaults seguros (null actor → ANONYMOUS).
 */
@ExtendWith(MockitoExtension.class)
class AuditEventPublisherTest {

    @Mock private ApplicationEventPublisher eventPublisher;
    @InjectMocks private AuditEventPublisher publisher;

    private ChainAuditEvent captureEvent() {
        ArgumentCaptor<ChainAuditEvent> captor = ArgumentCaptor.forClass(ChainAuditEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());
        return captor.getValue();
    }

    // -----------------------------------------------------------------------
    // publishAuthEvent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("publishAuthEvent dispara evento com campos corretos")
    void publishAuthEvent_PublishesCorrectEvent() {
        publisher.publishAuthEvent(
            AuditEventType.LOGIN_SUCCESS, "alice", "1.2.3.4", "jti-001", "login ok");

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.LOGIN_SUCCESS);
        assertThat(e.getActor()).isEqualTo("alice");
        assertThat(e.getIpAddress()).isEqualTo("1.2.3.4");
        assertThat(e.getSessionJti()).isEqualTo("jti-001");
        assertThat(e.getDetail()).isEqualTo("login ok");
        assertThat(e.getPayload()).containsEntry("eventCategory", "AUTH");
    }

    @Test
    @DisplayName("publishAuthEvent com actor null → ChainAuditEvent normaliza para 'ANONYMOUS'")
    void publishAuthEvent_NullActor_DefaultsToAnonymous() {
        publisher.publishAuthEvent(
            AuditEventType.LOGIN_FAILURE, null, "5.6.7.8", null, "bad password");

        ChainAuditEvent e = captureEvent();
        assertThat(e.getActor()).isEqualTo("ANONYMOUS");
    }

    // -----------------------------------------------------------------------
    // publishTokenEvent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("publishTokenEvent inclui eventCategory TOKEN no payload")
    void publishTokenEvent_ContainsTokenCategory() {
        publisher.publishTokenEvent(
            AuditEventType.TOKEN_ISSUED, "alice", "jti-a", "10.0.0.1");

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.TOKEN_ISSUED);
        assertThat(e.getActor()).isEqualTo("alice");
        assertThat(e.getSessionJti()).isEqualTo("jti-a");
        assertThat(e.getPayload()).containsEntry("eventCategory", "TOKEN");
    }

    @Test
    @DisplayName("publishTokenEvent com jti null → payload contém jti vazio (não null)")
    void publishTokenEvent_NullJti_StoredAsEmptyString() {
        publisher.publishTokenEvent(
            AuditEventType.TOKEN_BLACKLIST_VIOLATION, "ANONYMOUS", null, "1.2.3.4");

        ChainAuditEvent e = captureEvent();
        assertThat(e.getPayload()).containsKey("jti");
        assertThat(e.getPayload().get("jti")).isEqualTo("");
    }

    // -----------------------------------------------------------------------
    // publishAbacEvent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("publishAbacEvent inclui resource, action e reason nos campos corretos")
    void publishAbacEvent_ContainsAbacFields() {
        publisher.publishAbacEvent(
            AuditEventType.ABAC_DECISION_DENY, "bob",
            "/api/admin/users", "DELETE", "role ADMIN required");

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.ABAC_DECISION_DENY);
        assertThat(e.getActor()).isEqualTo("bob");
        assertThat(e.getResourcePath()).isEqualTo("/api/admin/users");
        assertThat(e.getDetail()).isEqualTo("role ADMIN required");
        assertThat(e.getPayload()).containsEntry("eventCategory", "ABAC");
        assertThat(e.getPayload()).containsEntry("action", "DELETE");
    }

    @Test
    @DisplayName("publishAbacEvent PERMIT funciona igual ao DENY")
    void publishAbacEvent_Permit_WorksCorrectly() {
        publisher.publishAbacEvent(
            AuditEventType.ABAC_DECISION_PERMIT, "admin",
            "/api/secret", "GET", "policy satisfied");

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.ABAC_DECISION_PERMIT);
    }

    // -----------------------------------------------------------------------
    // publishThreatEvent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("publishThreatEvent inclui riskScore e eventCategory THREAT")
    void publishThreatEvent_ContainsRiskScoreAndCategory() {
        publisher.publishThreatEvent(
            AuditEventType.IP_RATE_LIMIT_EXCEEDED, "10.0.0.1", "10.0.0.1", null, 42);

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.IP_RATE_LIMIT_EXCEEDED);
        assertThat(e.getIpAddress()).isEqualTo("10.0.0.1");
        assertThat(e.getPayload()).containsEntry("riskScore", 42);
        assertThat(e.getPayload()).containsEntry("eventCategory", "THREAT");
    }

    @Test
    @DisplayName("publishThreatEvent IP_BLOCKED_EXPLICIT com score=0 é publicado corretamente")
    void publishThreatEvent_BlockedExplicit_Score0() {
        publisher.publishThreatEvent(
            AuditEventType.IP_BLOCKED_EXPLICIT, "192.168.1.1", "192.168.1.1", null, 0);

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.IP_BLOCKED_EXPLICIT);
        assertThat(e.getPayload()).containsEntry("riskScore", 0);
    }

    // -----------------------------------------------------------------------
    // publishShieldEvent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("publishShieldEvent inclui userAgent, resourcePath, riskScore e categoria SHIELD")
    void publishShieldEvent_ContainsAllFields() {
        publisher.publishShieldEvent(
            AuditEventType.SHIELD_REQUEST_BLOCKED, "alice",
            "jti-shield", "10.0.0.1", "Mozilla/5.0", "/api/secret", 95);

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.SHIELD_REQUEST_BLOCKED);
        assertThat(e.getActor()).isEqualTo("alice");
        assertThat(e.getSessionJti()).isEqualTo("jti-shield");
        assertThat(e.getIpAddress()).isEqualTo("10.0.0.1");
        assertThat(e.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(e.getResourcePath()).isEqualTo("/api/secret");
        assertThat(e.getPayload()).containsEntry("riskScore", 95);
        assertThat(e.getPayload()).containsEntry("eventCategory", "SHIELD");
    }

    @Test
    @DisplayName("publishShieldEvent SHIELD_ALERT_TRIGGERED funciona corretamente")
    void publishShieldEvent_AlertTriggered_WorksCorrectly() {
        publisher.publishShieldEvent(
            AuditEventType.SHIELD_ALERT_TRIGGERED, "bob",
            "jti-y", "172.16.0.1", "curl/7.0", "/api/data", 65);

        ChainAuditEvent e = captureEvent();
        assertThat(e.getEventType()).isEqualTo(AuditEventType.SHIELD_ALERT_TRIGGERED);
        assertThat(e.getPayload()).containsEntry("riskScore", 65);
    }
}
