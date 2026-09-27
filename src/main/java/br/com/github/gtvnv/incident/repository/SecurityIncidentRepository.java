package br.com.github.gtvnv.incident.repository;

import br.com.github.gtvnv.incident.domain.IncidentStatus;
import br.com.github.gtvnv.incident.domain.SecurityIncident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, UUID> {

    List<SecurityIncident> findByStatusOrderByOpenedAtDesc(IncidentStatus status);

    List<SecurityIncident> findAllByOrderByOpenedAtDesc();

    // SLA de acknowledge: só se aplica enquanto ainda está OPEN.
    List<SecurityIncident> findByStatusAndAcknowledgeSlaDeadlineBeforeAndSlaBreachedFalse(
            IncidentStatus status, Instant now);

    // SLA de notificação: se aplica em OPEN ou ACKNOWLEDGED (ainda não notificado).
    List<SecurityIncident> findByStatusInAndNotifySlaDeadlineBeforeAndSlaBreachedFalse(
            List<IncidentStatus> statuses, Instant now);
}
