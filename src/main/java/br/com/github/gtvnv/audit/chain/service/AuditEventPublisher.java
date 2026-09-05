package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.event.ChainAuditEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Fachada semântica sobre ApplicationEventPublisher.
 * Os pontos de decisão de segurança injetam apenas este componente —
 * sem conhecimento de AuditChainEntry, AuditChainService ou hashing.
 */
@Component
@RequiredArgsConstructor
public class AuditEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    public void publishAuthEvent(AuditEventType type,
                                 String actor,
                                 String ipAddress,
                                 String jti,
                                 String detail) {
        publish(type, actor, jti, ipAddress, null, null, detail,
                Map.of("eventCategory", "AUTH"));
    }

    public void publishTokenEvent(AuditEventType type,
                                  String actor,
                                  String jti,
                                  String ipAddress) {
        publish(type, actor, jti, ipAddress, null, null,
                type.name() + " actor=" + actor,
                Map.of("eventCategory", "TOKEN", "jti", nullSafe(jti)));
    }

    public void publishAbacEvent(AuditEventType type,
                                 String actor,
                                 String resource,
                                 String action,
                                 String reason) {
        publish(type, actor, null, null, null, resource,
                reason,
                Map.of("eventCategory", "ABAC", "action", nullSafe(action), "reason", nullSafe(reason)));
    }

    public void publishThreatEvent(AuditEventType type,
                                   String actor,
                                   String ipAddress,
                                   String jti,
                                   int riskScore) {
        publish(type, actor, jti, ipAddress, null, null,
                type.name() + " ip=" + ipAddress + " score=" + riskScore,
                Map.of("eventCategory", "THREAT", "riskScore", riskScore));
    }

    public void publishShieldEvent(AuditEventType type,
                                   String actor,
                                   String jti,
                                   String ipAddress,
                                   String userAgent,
                                   String resourcePath,
                                   int riskScore) {
        publish(type, actor, jti, ipAddress, userAgent, resourcePath,
                type.name() + " actor=" + actor + " score=" + riskScore,
                Map.of("eventCategory", "SHIELD", "riskScore", riskScore));
    }

    private void publish(AuditEventType type,
                         String actor,
                         String jti,
                         String ipAddress,
                         String userAgent,
                         String resourcePath,
                         String detail,
                         Map<String, Object> payload) {
        eventPublisher.publishEvent(new ChainAuditEvent(
                this, type, actor, jti, ipAddress, userAgent, resourcePath, detail, payload
        ));
    }

    private String nullSafe(String value) {
        return value != null ? value : "";
    }
}
