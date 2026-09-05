package br.com.github.gtvnv.shield.listener;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.shield.domain.ShieldAlert;
import br.com.github.gtvnv.shield.event.ShieldThreatEvent;
import br.com.github.gtvnv.shield.repository.ShieldAlertRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class ShieldThreatListener {

    private final ShieldAlertRepository alertRepository;
    private final AuditEventPublisher chainPublisher;

    @Async
    @EventListener
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void onThreatDetected(ShieldThreatEvent event) {
        try {
            ShieldAlert alert = ShieldAlert.builder()
                    .timestamp(LocalDateTime.now())
                    .severity(event.getScoreResult().level())
                    .alertType(deriveAlertType(event.getScoreResult().reason()))
                    .actor(event.getActor())
                    .sessionJti(event.getJti())
                    .ipAddress(event.getIpAddress())
                    .userAgent(event.getUserAgent())
                    .resourcePath(event.getResourcePath())
                    .riskScore(event.getScoreResult().score())
                    .description(buildDescription(event))
                    .build();

            alertRepository.save(alert);

            AuditEventType chainType = event.isBlocked()
                    ? AuditEventType.SHIELD_REQUEST_BLOCKED
                    : AuditEventType.SHIELD_ALERT_TRIGGERED;
            chainPublisher.publishShieldEvent(chainType,
                    event.getActor(),
                    event.getJti(),
                    event.getIpAddress(),
                    event.getUserAgent(),
                    event.getResourcePath(),
                    event.getScoreResult().score());

        } catch (Exception e) {
            log.error("SHIELD: falha ao persistir alerta para jti={}: {}",
                    event.getJti(), e.getMessage());
        }
    }

    private String deriveAlertType(String reason) {
        if (reason == null) return "ANOMALY";
        if (reason.contains("LATERAL_MOVEMENT")) return "LATERAL_MOVEMENT";
        if (reason.contains("MULTI_IP"))         return "SESSION_HIJACK_SUSPECT";
        if (reason.contains("MULTI_AGENT"))      return "AGENT_ANOMALY";
        return "ANOMALY";
    }

    private String buildDescription(ShieldThreatEvent e) {
        return "actor=%s jti=%s ip=%s score=%d level=%s blocked=%s reason=[%s]".formatted(
                e.getActor(), e.getJti(), e.getIpAddress(),
                e.getScoreResult().score(), e.getScoreResult().level(),
                e.isBlocked(), e.getScoreResult().reason()
        );
    }
}
