package br.com.github.gtvnv.consent.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Versão vigente dos termos/política de privacidade que /auth/register exige
 * como consentVersion. Bump aqui sempre que o texto legal mudar — clientes
 * antigos param de conseguir registrar até mandarem a versão nova, o que é
 * o comportamento correto (consentimento tem que ser informado e específico).
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aegis.consent")
public class ConsentProperties {
    private String currentVersion;
    private String documentUrl;
}
