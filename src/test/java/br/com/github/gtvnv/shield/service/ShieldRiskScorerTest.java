package br.com.github.gtvnv.shield.service;

import br.com.github.gtvnv.shield.config.ShieldProperties;
import br.com.github.gtvnv.shield.domain.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes adversariais do ShieldRiskScorer.
 *
 * Verifica: sessão limpa (NONE), multi-IP, multi-agent, movimento lateral,
 * combinações acumulativas, cap de 100, limites exatos de ThreatLevel.
 */
@ExtendWith(MockitoExtension.class)
class ShieldRiskScorerTest {

    @Mock private ShieldProperties          props;
    @Mock private SessionFingerprintService fingerprintService;
    @Mock private LateralMovementDetector   lateralMovementDetector;

    @InjectMocks
    private ShieldRiskScorer scorer;

    private static final String JTI      = "test-jti-001";
    private static final String IP       = "10.0.0.1";
    private static final String AGENT    = "Mozilla/5.0";
    private static final String RESOURCE = "/api/secret";

    @BeforeEach
    void setupProps() {
        // Valores padrão do application.yml
        lenient().when(props.getScorePerExtraIp()).thenReturn(20);
        lenient().when(props.getScorePerExtraAgent()).thenReturn(10);
        lenient().when(props.getScoreLateralMovement()).thenReturn(35);
    }

    // -----------------------------------------------------------------------
    // Sessão limpa (sem anomalias)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sessão limpa: 1 IP, 1 agent, sem lateral movement → score=0, NONE")
    void score_CleanSession_ScoreZeroLevelNone() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(1L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(0);
        assertThat(result.level()).isEqualTo(ThreatLevel.NONE);
        assertThat(result.reason()).isBlank();
    }

    // -----------------------------------------------------------------------
    // Multi-IP
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("2 IPs distintos: penalidade +20 (1 extra × scorePerExtraIp), LOW")
    void score_TwoIps_Score20LevelLow() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(2L);  // 1 extra
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(20);
        assertThat(result.level()).isEqualTo(ThreatLevel.LOW);
        assertThat(result.reason()).contains("MULTI_IP");
    }

    @Test
    @DisplayName("3 IPs distintos: penalidade +40 (2 extras × 20), MEDIUM")
    void score_ThreeIps_Score40LevelMedium() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(3L);  // 2 extras
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(40);
        assertThat(result.level()).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    @DisplayName("5 IPs distintos: penalidade +80 (4 extras × 20), HIGH")
    void score_FiveIps_Score80LevelHigh() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(5L);  // 4 extras
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(80);
        assertThat(result.level()).isEqualTo(ThreatLevel.HIGH);
    }

    // -----------------------------------------------------------------------
    // Multi-Agent
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("2 User-Agents distintos: penalidade +10, LOW")
    void score_TwoAgents_Score10LevelLow() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(1L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(2L);  // 1 extra
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(10);
        assertThat(result.level()).isEqualTo(ThreatLevel.LOW);
        assertThat(result.reason()).contains("MULTI_AGENT");
    }

    @Test
    @DisplayName("4 User-Agents distintos: penalidade +30 (3 extras × 10), LOW (exatamente no limite)")
    void score_FourAgents_Score30LevelLow() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(1L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(4L);  // 3 extras
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(30);
        assertThat(result.level()).isEqualTo(ThreatLevel.LOW); // 30 ainda é LOW
    }

    // -----------------------------------------------------------------------
    // Movimento lateral
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Movimento lateral detectado: penalidade +35, MEDIUM")
    void score_LateralMovement_Score35LevelMedium() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(1L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(true);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(35);
        assertThat(result.level()).isEqualTo(ThreatLevel.MEDIUM);
        assertThat(result.reason()).contains("LATERAL_MOVEMENT");
    }

    // -----------------------------------------------------------------------
    // Combinações acumulativas
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("2 IPs + 2 agents: 20 + 10 = 30, LOW (fronteira exata)")
    void score_TwoIpsPlusTwoAgents_Score30LevelLow() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(2L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(2L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(30);
        assertThat(result.level()).isEqualTo(ThreatLevel.LOW);
    }

    @Test
    @DisplayName("2 IPs + movimento lateral: 20 + 35 = 55, MEDIUM")
    void score_TwoIpsPlusLateralMovement_Score55LevelMedium() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(2L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(true);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(55);
        assertThat(result.level()).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    @DisplayName("3 IPs + 2 agents + lateral: 40 + 10 + 35 = 85, CRITICAL")
    void score_ThreeIpsTwoAgentsLateral_Score85LevelCritical() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(3L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(2L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(true);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(85);
        assertThat(result.level()).isEqualTo(ThreatLevel.CRITICAL);
        assertThat(result.reason())
            .contains("MULTI_IP")
            .contains("MULTI_AGENT")
            .contains("LATERAL_MOVEMENT");
    }

    // -----------------------------------------------------------------------
    // Cap de 100 — score nunca ultrapassa 100
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Score bruto acima de 100 é capeado em 100 — CRITICAL")
    void score_RawScoreAbove100_CappedAt100() {
        // 6 IPs extras = 6 × 20 = 120 bruto → deve ser capeado em 100
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(7L);  // 6 extras
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        ShieldRiskScorer.ScoreResult result = scorer.score(JTI, IP, AGENT, RESOURCE);

        assertThat(result.score()).isEqualTo(100);
        assertThat(result.level()).isEqualTo(ThreatLevel.CRITICAL);
    }

    // -----------------------------------------------------------------------
    // Registro sempre é chamado (side effects)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("fingerprintService.record() é sempre chamado para registrar a sessão")
    void score_AlwaysCallsFingerprintRecord() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(1L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        scorer.score(JTI, IP, AGENT, RESOURCE);

        verify(fingerprintService).record(JTI, IP, AGENT);
    }

    @Test
    @DisplayName("lateralMovementDetector.recordAndDetect() é sempre chamado")
    void score_AlwaysCallsLateralMovementDetector() {
        when(fingerprintService.getDistinctIpCount(JTI)).thenReturn(1L);
        when(fingerprintService.getDistinctAgentCount(JTI)).thenReturn(1L);
        when(lateralMovementDetector.recordAndDetect(JTI, RESOURCE)).thenReturn(false);

        scorer.score(JTI, IP, AGENT, RESOURCE);

        verify(lateralMovementDetector).recordAndDetect(JTI, RESOURCE);
    }
}
