package br.com.github.gtvnv.privacy.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * Chave HMAC por titular usada pelo PrivacyGate para pseudonimizar o 'actor'
 * gravado no Ômega (audit_chain_entries).
 *
 * Propositalmente FORA do hardening WORM (docs/worm-hardening.sql) — precisa
 * aceitar DELETE: apagar a linha aqui é o mecanismo de crypto-shredding usado
 * por PrivacyGateService.forget() / AccountController#deleteAccount.
 */
@Entity
@Table(name = "privacy_subject_keys")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PrivacySubjectKey {

    /** username/subject id — mesma chave usada como 'actor' antes da pseudonimização. */
    @Id
    private String subjectId;

    @Column(nullable = false, length = 64)
    private String secretKeyBase64;

    @Column(nullable = false)
    private Instant createdAt;
}
