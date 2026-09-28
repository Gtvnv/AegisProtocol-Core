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
import br.com.github.gtvnv.shield.service.ShieldRiskScorer.ScoreResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IncidentOrchestratorServiceTest {

    @Mock private SecurityIncidentRepository repository;
    @Mock private AuditEventPublisher chainPublisher;
    @Mock private UserRepository userRepository;
    @Mock private NotificationProvider notificationProvider;

    private IncidentProperties properties;
    private NotificationProperties notificationProperties;
    private IncidentOrchestratorService service;

    @BeforeEach
    void setUp() {
        properties = new IncidentProperties();
        properties.setMinSeverity(ThreatLevel.HIGH);

        notificationProperties = new NotificationProperties();
        notificationProperties.setComplianceTeamEmail("compliance@aegisprotocol.example");

        service = new IncidentOrchestratorService(repository, properties, chainPublisher,
                userRepository, notificationProvider, notificationProperties);

        lenient().when(repository.save(any())).thenAnswer(inv -> {
            SecurityIncident i = inv.getArgument(0);
            if (i.getId() == null) {
                i.setId(UUID.randomUUID());
            }
            return i;
        });
    }

    private UserEntity userWithEmail(String username, String email) {
        return UserEntity.builder().username(username).email(email).build();
    }

    private ShieldThreatEvent threatEvent(String actor, ThreatLevel level, int score, boolean blocked) {
        return new ShieldThreatEvent(this, actor, "jti-1", "10.0.0.5", "Mozilla/5.0",
                "/api/secret", new ScoreResult(score, level, "LATERAL_MOVEMENT(+35)"), blocked);
    }

    // -----------------------------------------------------------------------
    // onThreatDetected — filtro de severidade
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Evento abaixo de minSeverity não abre incidente")
    void onThreatDetected_BelowMinSeverity_NoIncident() {
        service.onThreatDetected(threatEvent("alice", ThreatLevel.MEDIUM, 45, false));

        verifyNoInteractions(repository, chainPublisher);
    }

    @Test
    @DisplayName("Desabilitado (enabled=false) não abre incidente mesmo em CRITICAL")
    void onThreatDetected_Disabled_NoIncident() {
        properties.setEnabled(false);

        service.onThreatDetected(threatEvent("alice", ThreatLevel.CRITICAL, 95, true));

        verifyNoInteractions(repository, chainPublisher);
    }

    @Test
    @DisplayName("Evento HIGH abre incidente com SLA de HIGH e publica INCIDENT_OPENED")
    void onThreatDetected_High_OpensIncidentWithHighSla() {
        properties.setAcknowledgeSlaHoursHigh(24);
        properties.setNotifySlaHoursHigh(72);

        service.onThreatDetected(threatEvent("bob", ThreatLevel.HIGH, 70, false));

        ArgumentCaptor<SecurityIncident> captor = ArgumentCaptor.forClass(SecurityIncident.class);
        verify(repository).save(captor.capture());
        SecurityIncident saved = captor.getValue();

        assertThat(saved.getStatus()).isEqualTo(IncidentStatus.OPEN);
        assertThat(saved.getSeverity()).isEqualTo(ThreatLevel.HIGH);
        assertThat(saved.getActor()).isEqualTo("bob");
        assertThat(saved.isBlocked()).isFalse();
        assertThat(java.time.Duration.between(saved.getOpenedAt(), saved.getAcknowledgeSlaDeadline()).toHours()).isEqualTo(24);
        assertThat(java.time.Duration.between(saved.getOpenedAt(), saved.getNotifySlaDeadline()).toHours()).isEqualTo(72);

        verify(chainPublisher).publishIncidentEvent(
                eq(AuditEventType.INCIDENT_OPENED), eq("bob"), any(), contains("HIGH"));
    }

    @Test
    @DisplayName("Evento CRITICAL abre incidente com SLA mais curto (crítico)")
    void onThreatDetected_Critical_UsesCriticalSla() {
        properties.setAcknowledgeSlaHoursCritical(4);
        properties.setNotifySlaHoursCritical(24);

        service.onThreatDetected(threatEvent("attacker", ThreatLevel.CRITICAL, 95, true));

        ArgumentCaptor<SecurityIncident> captor = ArgumentCaptor.forClass(SecurityIncident.class);
        verify(repository).save(captor.capture());
        SecurityIncident saved = captor.getValue();

        assertThat(saved.isBlocked()).isTrue();
        assertThat(java.time.Duration.between(saved.getOpenedAt(), saved.getAcknowledgeSlaDeadline()).toHours()).isEqualTo(4);
        assertThat(java.time.Duration.between(saved.getOpenedAt(), saved.getNotifySlaDeadline()).toHours()).isEqualTo(24);
    }

    @Test
    @DisplayName("Falha ao salvar não propaga — listener é fire-and-forget, como o resto do Shield")
    void onThreatDetected_SaveThrows_DoesNotPropagate() {
        // doThrow (não when().thenThrow()): o setUp() já tem um thenAnswer para
        // save(any()) no mesmo mock — reabrir com when() reexecutaria aquele
        // answer durante o probe de registro do novo stub, com argumento nulo.
        reset(repository);
        doThrow(new RuntimeException("DB down")).when(repository).save(any());

        assertThatCode(() -> service.onThreatDetected(threatEvent("bob", ThreatLevel.HIGH, 70, false)))
                .doesNotThrowAnyException();
    }

    // -----------------------------------------------------------------------
    // acknowledge
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("acknowledge() move OPEN -> ACKNOWLEDGED e publica INCIDENT_ACKNOWLEDGED")
    void acknowledge_OpenIncident_MovesToAcknowledged() {
        UUID id = UUID.randomUUID();
        SecurityIncident open = SecurityIncident.builder().id(id).actor("bob").status(IncidentStatus.OPEN).build();
        when(repository.findById(id)).thenReturn(Optional.of(open));

        SecurityIncident result = service.acknowledge(id, "admin1");

        assertThat(result.getStatus()).isEqualTo(IncidentStatus.ACKNOWLEDGED);
        assertThat(result.getAcknowledgedBy()).isEqualTo("admin1");
        assertThat(result.getAcknowledgedAt()).isNotNull();
        verify(chainPublisher).publishIncidentEvent(
                eq(AuditEventType.INCIDENT_ACKNOWLEDGED), eq("admin1"), eq(id.toString()), any());
    }

    @Test
    @DisplayName("acknowledge() num incidente que não está OPEN lança IllegalStateException")
    void acknowledge_NotOpen_Throws() {
        UUID id = UUID.randomUUID();
        SecurityIncident resolved = SecurityIncident.builder().id(id).status(IncidentStatus.RESOLVED).build();
        when(repository.findById(id)).thenReturn(Optional.of(resolved));

        assertThatThrownBy(() -> service.acknowledge(id, "admin1"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("acknowledge() de id desconhecido lança NoSuchElementException")
    void acknowledge_UnknownId_Throws() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.acknowledge(id, "admin1"))
                .isInstanceOf(java.util.NoSuchElementException.class);
    }

    // -----------------------------------------------------------------------
    // notify
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("notify() com titular e autoridade OK marca os dois timestamps e vira NOTIFIED")
    void notify_BothSucceed_MarksNotifiedWithBothTimestamps() throws Exception {
        UUID id = UUID.randomUUID();
        SecurityIncident acknowledged = SecurityIncident.builder().id(id).actor("bob").status(IncidentStatus.ACKNOWLEDGED).build();
        when(repository.findById(id)).thenReturn(Optional.of(acknowledged));
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(userWithEmail("bob", "bob@example.com")));

        SecurityIncident result = service.notify(id, "admin1");

        assertThat(result.getStatus()).isEqualTo(IncidentStatus.NOTIFIED);
        assertThat(result.getSubjectNotifiedAt()).isNotNull();
        assertThat(result.getAuthorityNotifiedAt()).isNotNull();
        verify(notificationProvider).send(eq("bob@example.com"), any(), any());
        verify(notificationProvider).send(eq("compliance@aegisprotocol.example"), any(), any());
        verify(chainPublisher).publishIncidentEvent(
                eq(AuditEventType.INCIDENT_NOTIFIED), eq("admin1"), eq(id.toString()), contains("subject=true"));
    }

    @Test
    @DisplayName("notify() sem o titular encontrado (conta já excluída) não notifica o titular nem vira NOTIFIED")
    void notify_SubjectNotFound_SkipsSubjectAndStaysNotNotified() throws Exception {
        UUID id = UUID.randomUUID();
        SecurityIncident acknowledged = SecurityIncident.builder().id(id).actor("ghost").status(IncidentStatus.ACKNOWLEDGED).build();
        when(repository.findById(id)).thenReturn(Optional.of(acknowledged));
        when(userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        SecurityIncident result = service.notify(id, "admin1");

        assertThat(result.getStatus()).isEqualTo(IncidentStatus.ACKNOWLEDGED); // não avançou
        assertThat(result.getSubjectNotifiedAt()).isNull();
        assertThat(result.getAuthorityNotifiedAt()).isNotNull(); // autoridade ainda funciona independente
        verify(notificationProvider, times(1)).send(any(), any(), any()); // só a autoridade, nunca o titular
        verify(notificationProvider).send(eq("compliance@aegisprotocol.example"), any(), any());
    }

    @Test
    @DisplayName("notify() com envio ao titular falhando no provider mantém subjectNotifiedAt nulo, sem propagar a exceção")
    void notify_SubjectSendFails_KeepsSubjectNotifiedAtNull() throws Exception {
        UUID id = UUID.randomUUID();
        SecurityIncident acknowledged = SecurityIncident.builder().id(id).actor("bob").status(IncidentStatus.ACKNOWLEDGED).build();
        when(repository.findById(id)).thenReturn(Optional.of(acknowledged));
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(userWithEmail("bob", "bob@example.com")));
        doThrow(new IOException("SMTP indisponível")).when(notificationProvider).send(eq("bob@example.com"), any(), any());

        SecurityIncident result = service.notify(id, "admin1");

        assertThat(result.getSubjectNotifiedAt()).isNull();
        assertThat(result.getStatus()).isEqualTo(IncidentStatus.ACKNOWLEDGED); // não avançou pra NOTIFIED
    }

    @Test
    @DisplayName("notify() sem complianceTeamEmail configurado não notifica a autoridade nem vira NOTIFIED")
    void notify_NoComplianceEmailConfigured_SkipsAuthority() throws Exception {
        notificationProperties.setComplianceTeamEmail(null);
        UUID id = UUID.randomUUID();
        SecurityIncident acknowledged = SecurityIncident.builder().id(id).actor("bob").status(IncidentStatus.ACKNOWLEDGED).build();
        when(repository.findById(id)).thenReturn(Optional.of(acknowledged));
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(userWithEmail("bob", "bob@example.com")));

        SecurityIncident result = service.notify(id, "admin1");

        assertThat(result.getAuthorityNotifiedAt()).isNull();
        assertThat(result.getStatus()).isEqualTo(IncidentStatus.ACKNOWLEDGED);
        verify(notificationProvider, times(1)).send(any(), any(), any()); // só o titular
    }

    @Test
    @DisplayName("notify() num incidente já RESOLVED lança IllegalStateException, sem mandar nada")
    void notify_AlreadyResolved_ThrowsWithoutSending() {
        UUID id = UUID.randomUUID();
        SecurityIncident resolved = SecurityIncident.builder().id(id).status(IncidentStatus.RESOLVED).build();
        when(repository.findById(id)).thenReturn(Optional.of(resolved));

        assertThatThrownBy(() -> service.notify(id, "admin1")).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(notificationProvider);
    }

    // -----------------------------------------------------------------------
    // resolve
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("resolve() fecha o incidente com as notas e publica INCIDENT_RESOLVED")
    void resolve_ClosesIncidentWithNotes() {
        UUID id = UUID.randomUUID();
        SecurityIncident notified = SecurityIncident.builder().id(id).actor("bob").status(IncidentStatus.NOTIFIED).build();
        when(repository.findById(id)).thenReturn(Optional.of(notified));

        SecurityIncident result = service.resolve(id, "admin1", "Falso positivo, VPN corporativa.");

        assertThat(result.getStatus()).isEqualTo(IncidentStatus.RESOLVED);
        assertThat(result.getResolvedBy()).isEqualTo("admin1");
        assertThat(result.getResolutionNotes()).isEqualTo("Falso positivo, VPN corporativa.");
        assertThat(result.getResolvedAt()).isNotNull();
        verify(chainPublisher).publishIncidentEvent(
                eq(AuditEventType.INCIDENT_RESOLVED), eq("admin1"), eq(id.toString()), contains("Falso positivo"));
    }

    // -----------------------------------------------------------------------
    // checkOverdueSlas
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("checkOverdueSlas marca slaBreached e publica INCIDENT_SLA_BREACHED para cada incidente vencido")
    void checkOverdueSlas_MarksBreachedAndAudits() {
        SecurityIncident overdueAck = SecurityIncident.builder()
                .id(UUID.randomUUID()).actor("alice").status(IncidentStatus.OPEN).severity(ThreatLevel.HIGH).build();
        SecurityIncident overdueNotify = SecurityIncident.builder()
                .id(UUID.randomUUID()).actor("bob").status(IncidentStatus.ACKNOWLEDGED).severity(ThreatLevel.CRITICAL).build();

        when(repository.findByStatusAndAcknowledgeSlaDeadlineBeforeAndSlaBreachedFalse(eq(IncidentStatus.OPEN), any()))
                .thenReturn(List.of(overdueAck));
        when(repository.findByStatusInAndNotifySlaDeadlineBeforeAndSlaBreachedFalse(
                eq(List.of(IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED)), any()))
                .thenReturn(List.of(overdueNotify));

        service.checkOverdueSlas();

        assertThat(overdueAck.isSlaBreached()).isTrue();
        assertThat(overdueNotify.isSlaBreached()).isTrue();
        verify(repository, times(2)).save(any());
        verify(chainPublisher).publishIncidentEvent(eq(AuditEventType.INCIDENT_SLA_BREACHED), eq("alice"), any(), any());
        verify(chainPublisher).publishIncidentEvent(eq(AuditEventType.INCIDENT_SLA_BREACHED), eq("bob"), any(), any());
    }

    @Test
    @DisplayName("checkOverdueSlas sem nada vencido não faz nada")
    void checkOverdueSlas_NothingOverdue_NoOp() {
        when(repository.findByStatusAndAcknowledgeSlaDeadlineBeforeAndSlaBreachedFalse(any(), any())).thenReturn(List.of());
        when(repository.findByStatusInAndNotifySlaDeadlineBeforeAndSlaBreachedFalse(any(), any())).thenReturn(List.of());

        service.checkOverdueSlas();

        verify(repository, never()).save(any());
        verifyNoInteractions(chainPublisher);
    }

    @Test
    @DisplayName("checkOverdueSlas desabilitado não consulta nada")
    void checkOverdueSlas_Disabled_DoesNothing() {
        properties.setEnabled(false);

        service.checkOverdueSlas();

        verifyNoInteractions(repository, chainPublisher);
    }
}
