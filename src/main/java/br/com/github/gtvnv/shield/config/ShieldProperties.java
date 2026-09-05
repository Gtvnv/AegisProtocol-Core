package br.com.github.gtvnv.shield.config;

import br.com.github.gtvnv.shield.domain.ThreatLevel;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "aegis.shield")
public class ShieldProperties {

    /** Ativa ou desativa o módulo S.H.I.E.L.D. inteiramente. */
    private boolean enabled = true;

    /** Nível de ameaça a partir do qual a requisição é bloqueada. */
    private ThreatLevel blockThreshold = ThreatLevel.CRITICAL;

    /** Nível de ameaça a partir do qual um alerta é persistido no banco. */
    private ThreatLevel alertThreshold = ThreatLevel.HIGH;

    /** Número máximo de recursos distintos por sessão JWT antes de acionar lateral movement. */
    private int lateralMovementResourceLimit = 10;

    /** Janela de tempo (minutos) para contar recursos distintos por sessão. */
    private int sessionWindowMinutes = 30;

    /** Pontuação de risco adicionada por cada IP extra usando o mesmo JTI. */
    private int scorePerExtraIp = 20;

    /** Pontuação de risco adicionada por cada User-Agent extra no mesmo JTI. */
    private int scorePerExtraAgent = 10;

    /** Pontuação de risco adicionada ao detectar movimento lateral. */
    private int scoreLateralMovement = 35;

    /** Pontuação de risco adicionada por divergência de fingerprint. */
    private int scoreFingerprintMismatch = 25;
}
