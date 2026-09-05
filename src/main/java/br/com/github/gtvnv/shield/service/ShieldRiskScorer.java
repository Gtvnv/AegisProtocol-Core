package br.com.github.gtvnv.shield.service;

import br.com.github.gtvnv.shield.config.ShieldProperties;
import br.com.github.gtvnv.shield.domain.ThreatLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Calcula o risk score composto para uma requisição.
 *
 * Fatores de pontuação (configuráveis via ShieldProperties):
 *   +scorePerExtraIp         por cada IP extra usando o mesmo JTI (acima de 1)
 *   +scorePerExtraAgent      por cada User-Agent extra no mesmo JTI (acima de 1)
 *   +scoreLateralMovement    se movimento lateral detectado (recursos distintos >= limite)
 *   +scoreFingerprintMismatch se IP ou agent divergem do fingerprint original da sessão
 *
 * Range: 0–100+ → mapeado para ThreatLevel via ThreatLevel.fromScore()
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ShieldRiskScorer {

    private final ShieldProperties props;
    private final SessionFingerprintService fingerprintService;
    private final LateralMovementDetector lateralMovementDetector;

    public record ScoreResult(int score, ThreatLevel level, String reason) {}

    /**
     * Computa o risk score para uma requisição autenticada.
     *
     * @param jti          JWT ID do token (nunca null neste path)
     * @param ipAddress    IP da requisição
     * @param userAgent    User-Agent da requisição
     * @param resourcePath URI acessada
     */
    public ScoreResult score(String jti, String ipAddress, String userAgent, String resourcePath) {
        int total = 0;
        StringBuilder reason = new StringBuilder();

        // 1. Registrar acesso e checar fingerprint
        fingerprintService.record(jti, ipAddress, userAgent);

        long ipCount    = fingerprintService.getDistinctIpCount(jti);
        long agentCount = fingerprintService.getDistinctAgentCount(jti);

        if (ipCount > 1) {
            int penalty = (int) (ipCount - 1) * props.getScorePerExtraIp();
            total += penalty;
            reason.append("MULTI_IP(+").append(penalty).append(") ");
        }

        if (agentCount > 1) {
            int penalty = (int) (agentCount - 1) * props.getScorePerExtraAgent();
            total += penalty;
            reason.append("MULTI_AGENT(+").append(penalty).append(") ");
        }

        // 2. Detectar movimento lateral
        boolean lateralDetected = lateralMovementDetector.recordAndDetect(jti, resourcePath);
        if (lateralDetected) {
            total += props.getScoreLateralMovement();
            reason.append("LATERAL_MOVEMENT(+").append(props.getScoreLateralMovement()).append(") ");
        }

        int finalScore = Math.min(total, 100);
        ThreatLevel level = ThreatLevel.fromScore(finalScore);

        if (level.isAtLeast(ThreatLevel.MEDIUM)) {
            log.warn("SHIELD RISK: jti={} ip={} score={} level={} reason={}",
                    jti, ipAddress, finalScore, level, reason);
        }

        return new ScoreResult(finalScore, level, reason.toString().trim());
    }
}
