package br.com.github.gtvnv.incident.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.domain.entity.UserEntity;
import br.com.github.gtvnv.domain.repository.UserRepository;
import br.com.github.gtvnv.incident.config.IncidentProperties;
import br.com.github.gtvnv.incident.domain.IncidentStatus;
import br.com.github.gtvnv.incident.domain.SecurityIncident;
import br.com.github.gtvnv.incident.repository.SecurityIncidentRepository;
import br.com.github.gtvnv.notification.config.NotificationProperties;
import br.com.github.gtvnv.notification.service.NotificationProvider;
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

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

/**
 * Satélite Incident Response Orchestrator — transforma um ShieldThreatEvent
 * grave num incidente formal, com SLA e ciclo de vida rastreável. Fecha
 * ISO A.5.26 e viabiliza LGPD Art. 48.
 *
 * notify() manda e-mail de verdade (via NotificationProvider — ver satélite
 * de notificação real): titular (e-mail resolvido via UserRepository a
 * partir de incident.actor) e o time de compliance interno, que é quem de
 * fato faz o registro formal na ANPD (a autoridade não expõe uma API
 * pública de notificação em tempo real). O status só avança pra NOTIFIED
 * quando AMBOS os envios têm sucesso — envio parcial fica registrado com
 * os timestamps que realmente aconteceram, sem fingir que deu tudo certo.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentOrchestratorService {

    private final SecurityIncidentRepository repository;
    private final IncidentProperties properties;
    private final AuditEventPublisher chainPublisher;
    private final UserRepository userRepository;
    private final NotificationProvider notificationProvider;
    private final NotificationProperties notificationProperties;

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

    /**
     * Manda e-mail de verdade pro titular e pro time de compliance. Envio
     * parcial fica registrado com exatidão — status só vira NOTIFIED quando
     * os dois têm sucesso; falha em qualquer um mantém o incidente elegível
     * pra cobrança de SLA (checkOverdueSlas continua vendo como pendente).
     */
    @Transactional
    public SecurityIncident notify(UUID incidentId, String byActor) {
        SecurityIncident incident = findOrThrow(incidentId);
        if (incident.getStatus() == IncidentStatus.RESOLVED) {
            throw new IllegalStateException("Incidente %s já está RESOLVED".formatted(incidentId));
        }

        boolean subjectOk = notifySubject(incident);
        boolean authorityOk = notifyAuthority(incident);

        if (subjectOk && authorityOk) {
            incident.setStatus(IncidentStatus.NOTIFIED);
        }
        repository.save(incident);

        chainPublisher.publishIncidentEvent(AuditEventType.INCIDENT_NOTIFIED,
                byActor, incidentId.toString(),
                "Notify attempted: subject=%s authority=%s".formatted(subjectOk, authorityOk));
        log.warn("INCIDENT NOTIFY id={} subject={} authority={}", incidentId, subjectOk, authorityOk);
        return incident;
    }

    private boolean notifySubject(SecurityIncident incident) {
        if (!notificationProperties.isEnabled()) {
            return false;
        }
        Optional<UserEntity> user = userRepository.findByUsername(incident.getActor());
        if (user.isEmpty()) {
            log.warn("IncidentOrchestrator: titular '{}' não encontrado (conta já excluída?) — não dá pra notificar por e-mail.",
                    incident.getActor());
            return false;
        }
        try {
            notificationProvider.send(user.get().getEmail(),
                    "Alerta de segurança na sua conta",
                    "Detectamos uma atividade de segurança na sua conta em %s (severidade %s). "
                            .formatted(incident.getOpenedAt(), incident.getSeverity())
                            + "Se não foi você, contate o suporte imediatamente.");
            incident.setSubjectNotifiedAt(Instant.now());
            return true;
        } catch (IOException e) {
            log.error("IncidentOrchestrator: falha ao notificar titular do incidente {}: {}", incident.getId(), e.getMessage());
            return false;
        }
    }

    private boolean notifyAuthority(SecurityIncident incident) {
        if (!notificationProperties.isEnabled() || notificationProperties.getComplianceTeamEmail() == null
                || notificationProperties.getComplianceTeamEmail().isBlank()) {
            log.warn("IncidentOrchestrator: aegis.notification.compliance-team-email não configurado — notificação à autoridade indisponível.");
            return false;
        }
        try {
            notificationProvider.send(notificationProperties.getComplianceTeamEmail(),
                    "Incidente de segurança requer avaliação (LGPD Art. 48)",
                    "Incidente %s aberto em %s, severidade %s, ator=%s. Avalie se há dever de comunicação à ANPD."
                            .formatted(incident.getId(), incident.getOpenedAt(), incident.getSeverity(), incident.getActor()));
            incident.setAuthorityNotifiedAt(Instant.now());
            return true;
        } catch (IOException e) {
            log.error("IncidentOrchestrator: falha ao notificar time de compliance do incidente {}: {}", incident.getId(), e.getMessage());
            return false;
        }
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
