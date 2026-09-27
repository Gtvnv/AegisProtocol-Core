package br.com.github.gtvnv.incident.domain;

import br.com.github.gtvnv.shield.domain.ThreatLevel;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Satélite Incident Response Orchestrator: um ShieldThreatEvent grave vira
 * um incidente formal aqui, com prazos de SLA e ciclo de vida rastreável —
 * não é mais só uma linha no log do ShieldAlert.
 *
 * Fecha ISO A.5.26 (resposta a incidentes) e viabiliza LGPD Art. 48
 * (notificação de incidente à ANPD e ao titular).
 */
@Entity
@Table(name = "security_incidents")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ThreatLevel severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private IncidentStatus status;

    @Column(nullable = false)
    private String actor;

    private String sessionJti;
    private String ipAddress;
    private String resourcePath;
    private boolean blocked;

    @Column(columnDefinition = "TEXT")
    private String summary;

    @Column(nullable = false)
    private Instant openedAt;

    @Column(nullable = false)
    private Instant acknowledgeSlaDeadline;

    @Column(nullable = false)
    private Instant notifySlaDeadline;

    @Builder.Default
    private boolean slaBreached = false;

    private Instant acknowledgedAt;
    private String acknowledgedBy;

    private Instant subjectNotifiedAt;
    private Instant authorityNotifiedAt;

    private Instant resolvedAt;
    private String resolvedBy;

    @Column(columnDefinition = "TEXT")
    private String resolutionNotes;
}
