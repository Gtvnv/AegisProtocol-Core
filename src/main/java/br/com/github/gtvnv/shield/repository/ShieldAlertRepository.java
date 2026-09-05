package br.com.github.gtvnv.shield.repository;

import br.com.github.gtvnv.shield.domain.ShieldAlert;
import br.com.github.gtvnv.shield.domain.ThreatLevel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface ShieldAlertRepository extends JpaRepository<ShieldAlert, String> {

    List<ShieldAlert> findByActor(String actor);
    List<ShieldAlert> findBySeverity(ThreatLevel severity);
    List<ShieldAlert> findByIpAddress(String ipAddress);
    List<ShieldAlert> findByTimestampBetween(LocalDateTime from, LocalDateTime to);
    List<ShieldAlert> findByAlertType(String alertType);
}
