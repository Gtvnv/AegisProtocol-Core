package br.com.github.gtvnv.shield.domain;

public enum ThreatLevel {
    NONE(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4);

    private final int severity;

    ThreatLevel(int severity) {
        this.severity = severity;
    }

    public int getSeverity() {
        return severity;
    }

    public static ThreatLevel fromScore(int riskScore) {
        if (riskScore <= 0)  return NONE;
        if (riskScore <= 30) return LOW;
        if (riskScore <= 60) return MEDIUM;
        if (riskScore <= 80) return HIGH;
        return CRITICAL;
    }

    public boolean isAtLeast(ThreatLevel other) {
        return this.severity >= other.severity;
    }
}
