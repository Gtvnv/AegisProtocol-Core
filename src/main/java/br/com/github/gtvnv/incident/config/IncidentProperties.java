package br.com.github.gtvnv.incident.config;

import br.com.github.gtvnv.shield.domain.ThreatLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Satélite Incident Response Orchestrator. Nem todo ShieldThreatEvent vira
 * incidente formal — só os de nível >= minSeverity (fadiga de alerta é
 * real; os demais continuam só como ShieldAlert, como já era). Prazos de
 * SLA em horas: acknowledge = "alguém viu isso", notify = titular + ANPD
 * avisados (LGPD Art. 48 não fixa um prazo em horas como o GDPR — 72h aqui
 * é o valor mais conhecido do mercado, ajuste para o que sua política interna
 * definir).
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.incident")
public class IncidentProperties {
    private boolean enabled = true;
    private ThreatLevel minSeverity = ThreatLevel.HIGH;

    private int acknowledgeSlaHoursCritical = 4;
    private int notifySlaHoursCritical = 24;
    private int acknowledgeSlaHoursHigh = 24;
    private int notifySlaHoursHigh = 72;

    private String slaCheckCron = "0 */15 * * * *"; // a cada 15 min
}
