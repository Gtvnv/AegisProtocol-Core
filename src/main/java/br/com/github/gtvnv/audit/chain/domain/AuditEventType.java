package br.com.github.gtvnv.audit.chain.domain;

public enum AuditEventType {

    // Autenticação
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT_SUCCESS,
    ACCOUNT_CREATED,

    // Tokens
    TOKEN_ISSUED,
    REFRESH_TOKEN_ISSUED,
    TOKEN_REFRESHED,
    TOKEN_BLACKLIST_VIOLATION,
    REFRESH_TOKEN_USED_AS_ACCESS,

    // Controle de acesso (ABAC)
    ABAC_DECISION_PERMIT,
    ABAC_DECISION_DENY,

    // Ameaças (rate-limit e bloqueio)
    IP_RATE_LIMIT_EXCEEDED,
    IP_BLOCKED_EXPLICIT,

    // S.H.I.E.L.D.
    SHIELD_ALERT_TRIGGERED,
    SHIELD_REQUEST_BLOCKED
}
