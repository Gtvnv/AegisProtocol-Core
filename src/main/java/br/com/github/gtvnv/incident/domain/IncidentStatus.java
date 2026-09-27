package br.com.github.gtvnv.incident.domain;

/** Ciclo de vida linear: OPEN -> ACKNOWLEDGED -> NOTIFIED -> RESOLVED. */
public enum IncidentStatus {
    OPEN,
    ACKNOWLEDGED,
    NOTIFIED,
    RESOLVED
}
