package br.com.github.gtvnv.incident.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.incident.config.IncidentProperties;
import br.com.github.gtvnv.incident.domain.IncidentStatus;
import br.com.github.gtvnv.incident.domain.SecurityIncident;
import br.com.github.gtvnv.incident.repository.SecurityIncidentRepository;
import br.com.github.gtvnv.shield.domain.ThreatLevel;
import br.com.github.gtvnv.shield.event.ShieldThreatEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * Satélite Incident Response Orchestrator — transforma um ShieldThreatEvent
 * grave num incidente formal, com SLA e ciclo de vida rastreável. Fecha
 * ISO A.5.26 e viabiliza LGPD Art. 48.
 *
 * A notificação em si (notify()) é simulada — não há integração real de
 * e-mail/SMS/API da ANPD neste satélite. O que ele entrega é a parte que
 * fica: o registro de QUE a notificação aconteceu, QUANDO, e a cobrança de
 * SLA automática se ninguém agir a tempo. Plugar um provedor real de
 * notificação é a próxima peça, não este satélite.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentOrchestratorService {

    private final SecurityIncidentRepository repository;
    private final IncidentProperties properties;
    private final AuditEventPublisher chainPublisher;

    @Async
    @EventListener
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void onThreatDetected(ShieldThreatEvent event) {
        if (!properties.isEnabled()) {
            return;
        }
        ThreatLevel level = event.getScoreResult().level();
        if (!level.isAtLeast(properties.getMinSeverity())) {
            return; // abaixo do limiar — fica só como ShieldAlert, sem virar incidente
        }

        try {
            openIncident(event, level);
        } catch (Exception e) {
            log.error("IncidentOrchestrator: falha ao abrir incidente para actor={}: {}",
                    event.getActor(), e.getMessage());
        }
    }

    private SecurityIncident openIncident(ShieldThreatEvent event, ThreatLevel level) {
        Instant now = Instant.now();
        boolean critical = level == ThreatLevel.CRITICAL;

        SecurityIncident incident = repository.save(SecurityIncident.builder()
                .severity(level)
                .status(IncidentStatus.OPEN)
                .actor(event.getActor())
                .sessionJti(event.getJti())
                .ipAddress(event.getIpAddress())
                .resourcePath(event.getResourcePath())
                .blocked(event.isBlocked())
                .summary("SHIELD score=%d level=%s blocked=%s reason=[%s]".formatted(
                        event.getScoreResult().score(), level, event.isBlocked(), event.getScoreResult().reason()))
                .openedAt(now)
                .acknowledgeSlaDeadline(now.plus(
                        critical ? properties.getAcknowledgeSlaHoursCritical() : properties.getAcknowledgeSlaHoursHigh(),
                        ChronoUnit.HOURS))
                .notifySlaDeadline(now.plus(
                        critical ? properties.getNotifySlaHoursCritical() : properties.getNotifySlaHoursHigh(),
                        ChronoUnit.HOURS))
                .build());

        chainPublisher.publishIncidentEvent(AuditEventType.INCIDENT_OPENED,
                event.getActor(), incident.getId().toString(),
                "Incident opened, severity=" + level);

        log.warn("INCIDENT OPENED id={} actor={} severity={} ack_by={} notify_by={}",
                incident.getId(), event.getActor(), level,
                incident.getAcknowledgeSlaDeadline(), incident.getNotifySlaDeadline());

        return incident;
    }

    @Transactional
    public SecurityIncident acknowledge(UUID incidentId, String byActor) {
        SecurityIncident incident = findOrThrow(incidentId);
        if (incident.getStatus() != IncidentStatus.OPEN) {
            throw new IllegalStateException("Incidente %s não está OPEN (status atual: %s)"
                    .formatted(incidentId, incident.getStatus()));
        }
        incident.setStatus(IncidentStatus.ACKNOWLEDGED);
        incident.setAcknowledgedAt(Instant.now());
        incident.setAcknowledgedBy(byActor);
        repository.save(incident);

        chainPublisher.publishIncidentEvent(AuditEventType.INCIDENT_ACKNOWLEDGED,
                byActor, incidentId.toString(), "Incident acknowledged");
        return incident;
    }

    /** Simulado — ver javadoc da classe. Marca titular + ANPD como notificados. */
    @Transactional
    public SecurityIncident notify(UUID incidentId, String byActor) {
        SecurityIncident incident = findOrThrow(incidentId);
        if (incident.getStatus() == IncidentStatus.RESOLVED) {
            throw new IllegalStateException("Incidente %s já está RESOLVED".formatted(incidentId));
        }
        Instant now = Instant.now();
        incident.setStatus(IncidentStatus.NOTIFIED);
        incident.setSubjectNotifiedAt(now);
        incident.setAuthorityNotifiedAt(now);
        repository.save(incident);

        chainPublisher.publishIncidentEvent(AuditEventType.INCIDENT_NOTIFIED,
                byActor, incidentId.toString(), "Subject and authority (ANPD) notified");
        log.warn("INCIDENT NOTIFIED id={} — titular e ANPD marcados como avisados (simulado).", incidentId);
        return incident;
    }

    @Transactional
    public SecurityIncident resolve(UUID incidentId, String byActor, String resolutionNotes) {
        SecurityIncident incident = findOrThrow(incidentId);
        incident.setStatus(IncidentStatus.RESOLVED);
        incident.setResolvedAt(Instant.now());
        incident.setResolvedBy(byActor);
        incident.setResolutionNotes(resolutionNotes);
        repository.save(incident);

        chainPublisher.publishIncidentEvent(AuditEventType.INCIDENT_RESOLVED,
                byActor, incidentId.toString(), "Incident resolved: " + resolutionNotes);
        return incident;
    }

    @Scheduled(cron = "${aegis.incident.sla-check-cron:0 */15 * * * *}")
    public void checkOverdueSlas() {
        if (!properties.isEnabled()) {
            return;
        }
        Instant now = Instant.now();
        List<SecurityIncident> overdue = new java.util.ArrayList<>();
        overdue.addAll(repository.findByStatusAndAcknowledgeSlaDeadlineBeforeAndSlaBreachedFalse(IncidentStatus.OPEN, now));
        overdue.addAll(repository.findByStatusInAndNotifySlaDeadlineBeforeAndSlaBreachedFalse(
                List.of(IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED), now));

        for (SecurityIncident incident : overdue) {
            incident.setSlaBreached(true);
            repository.save(incident);
            chainPublisher.publishIncidentEvent(AuditEventType.INCIDENT_SLA_BREACHED,
                    incident.getActor(), incident.getId().toString(),
                    "SLA breached — status=" + incident.getStatus());
            log.error("INCIDENT SLA BREACHED id={} actor={} status={} severity={}",
                    incident.getId(), incident.getActor(), incident.getStatus(), incident.getSeverity());
        }
    }

    private SecurityIncident findOrThrow(UUID incidentId) {
        return repository.findById(incidentId)
                .orElseThrow(() -> new NoSuchElementException("Incidente não encontrado: " + incidentId));
    }
}
