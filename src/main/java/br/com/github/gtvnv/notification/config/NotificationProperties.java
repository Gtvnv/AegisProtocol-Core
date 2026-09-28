package br.com.github.gtvnv.notification.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Satélite Incident Notification real (fecha LGPD Art. 48 de vez — a versão
 * simulada do PR #6 só registrava a intenção, não mandava nada).
 *
 * complianceTeamEmail é quem recebe o aviso "para a ANPD" — a API da ANPD
 * não tem um endpoint público de notificação em tempo real; na prática o
 * fluxo real é avisar o time/DPO responsável, que faz o registro formal.
 * Sem essa config, a notificação "à autoridade" fica indisponível (retorna
 * falha) até alguém configurar.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.notification")
public class NotificationProperties {
    private boolean enabled = true;
    private String fromAddress = "no-reply@aegisprotocol.example";
    private String complianceTeamEmail;
}
