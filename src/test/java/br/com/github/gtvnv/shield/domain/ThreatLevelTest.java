package br.com.github.gtvnv.shield.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Testa as fronteiras exatas do mapeamento score → ThreatLevel
 * e a semântica de isAtLeast().
 */
class ThreatLevelTest {

    // -----------------------------------------------------------------------
    // Mapeamento fromScore — fronteiras críticas
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "score={0} → {1}")
    @CsvSource({
        "-999, NONE",
        "-1,   NONE",
        "0,    NONE",
        "1,    LOW",
        "15,   LOW",
        "30,   LOW",
        "31,   MEDIUM",
        "45,   MEDIUM",
        "60,   MEDIUM",
        "61,   HIGH",
        "70,   HIGH",
        "80,   HIGH",
        "81,   CRITICAL",
        "90,   CRITICAL",
        "100,  CRITICAL",
        "999,  CRITICAL"
    })
    @DisplayName("fromScore mapeia score para o nível correto em todas as fronteiras")
    void fromScore_AllBoundaries(int score, ThreatLevel expected) {
        assertThat(ThreatLevel.fromScore(score)).isEqualTo(expected);
    }

    @Test
    @DisplayName("Fronteira exata LOW→MEDIUM: 30=LOW, 31=MEDIUM")
    void fromScore_LowMediumBoundary_IsExact() {
        assertThat(ThreatLevel.fromScore(30)).isEqualTo(ThreatLevel.LOW);
        assertThat(ThreatLevel.fromScore(31)).isEqualTo(ThreatLevel.MEDIUM);
    }

    @Test
    @DisplayName("Fronteira exata MEDIUM→HIGH: 60=MEDIUM, 61=HIGH")
    void fromScore_MediumHighBoundary_IsExact() {
        assertThat(ThreatLevel.fromScore(60)).isEqualTo(ThreatLevel.MEDIUM);
        assertThat(ThreatLevel.fromScore(61)).isEqualTo(ThreatLevel.HIGH);
    }

    @Test
    @DisplayName("Fronteira exata HIGH→CRITICAL: 80=HIGH, 81=CRITICAL")
    void fromScore_HighCriticalBoundary_IsExact() {
        assertThat(ThreatLevel.fromScore(80)).isEqualTo(ThreatLevel.HIGH);
        assertThat(ThreatLevel.fromScore(81)).isEqualTo(ThreatLevel.CRITICAL);
    }

    // -----------------------------------------------------------------------
    // isAtLeast — semântica de ordenação
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CRITICAL.isAtLeast: true para todos os níveis (é o máximo)")
    void isAtLeast_CriticalIsAtLeastAll() {
        for (ThreatLevel level : ThreatLevel.values()) {
            assertThat(ThreatLevel.CRITICAL.isAtLeast(level))
                .as("CRITICAL.isAtLeast(%s)", level)
                .isTrue();
        }
    }

    @Test
    @DisplayName("NONE.isAtLeast: true apenas para NONE (é o mínimo)")
    void isAtLeast_NoneIsOnlyAtLeastNone() {
        assertThat(ThreatLevel.NONE.isAtLeast(ThreatLevel.NONE)).isTrue();
        assertThat(ThreatLevel.NONE.isAtLeast(ThreatLevel.LOW)).isFalse();
        assertThat(ThreatLevel.NONE.isAtLeast(ThreatLevel.MEDIUM)).isFalse();
        assertThat(ThreatLevel.NONE.isAtLeast(ThreatLevel.HIGH)).isFalse();
        assertThat(ThreatLevel.NONE.isAtLeast(ThreatLevel.CRITICAL)).isFalse();
    }

    @Test
    @DisplayName("HIGH.isAtLeast(MEDIUM) = true, HIGH.isAtLeast(CRITICAL) = false")
    void isAtLeast_High_CorrectBoundaries() {
        assertThat(ThreatLevel.HIGH.isAtLeast(ThreatLevel.NONE)).isTrue();
        assertThat(ThreatLevel.HIGH.isAtLeast(ThreatLevel.LOW)).isTrue();
        assertThat(ThreatLevel.HIGH.isAtLeast(ThreatLevel.MEDIUM)).isTrue();
        assertThat(ThreatLevel.HIGH.isAtLeast(ThreatLevel.HIGH)).isTrue();
        assertThat(ThreatLevel.HIGH.isAtLeast(ThreatLevel.CRITICAL)).isFalse();
    }

    @Test
    @DisplayName("isAtLeast é reflexivo: qualquer nível isAtLeast ele mesmo")
    void isAtLeast_IsReflexive() {
        for (ThreatLevel level : ThreatLevel.values()) {
            assertThat(level.isAtLeast(level))
                .as("%s.isAtLeast(%s)", level, level)
                .isTrue();
        }
    }

    // -----------------------------------------------------------------------
    // Severidade numérica — garante ordenação correta
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Severidade numérica está ordenada NONE < LOW < MEDIUM < HIGH < CRITICAL")
    void severity_IsStrictlyOrdered() {
        assertThat(ThreatLevel.NONE.getSeverity()).isLessThan(ThreatLevel.LOW.getSeverity());
        assertThat(ThreatLevel.LOW.getSeverity()).isLessThan(ThreatLevel.MEDIUM.getSeverity());
        assertThat(ThreatLevel.MEDIUM.getSeverity()).isLessThan(ThreatLevel.HIGH.getSeverity());
        assertThat(ThreatLevel.HIGH.getSeverity()).isLessThan(ThreatLevel.CRITICAL.getSeverity());
    }
}
