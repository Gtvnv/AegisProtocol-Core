package br.com.github.gtvnv.consent.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * Satélite Consent Ledger: registro de que um titular consentiu com uma
 * versão específica dos termos/política de privacidade.
 *
 * Tabela normal (mutável, apagável) — a evidência tamper-proof de que o
 * consentimento aconteceu vive no Ômega (AuditEventType.CONSENT_GIVEN via
 * ConsentService). Esta tabela é só o índice operacional "qual a versão
 * vigente que este titular aceitou", por isso pode ser apagada de verdade
 * na exclusão de conta (ver AccountController) — diferente de
 * privacy_subject_keys, aqui não tem WORM nem HMAC envolvido.
 */
@Entity
@Table(name = "consent_records")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConsentRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String subjectId; // username

    @Column(nullable = false)
    private String version;

    @Column(nullable = false)
    private Instant consentedAt;

    private String ipAddress;

    /** null = consentimento em vigor; preenchido quando o titular revoga. */
    private Instant revokedAt;
}
