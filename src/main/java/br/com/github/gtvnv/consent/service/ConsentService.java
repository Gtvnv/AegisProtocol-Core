package br.com.github.gtvnv.consent.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.consent.config.ConsentProperties;
import br.com.github.gtvnv.consent.domain.ConsentRecord;
import br.com.github.gtvnv.consent.repository.ConsentRecordRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * Satélite Consent Ledger — captura consentimento versionado no registro e
 * encadeia a evidência no Ômega (CONSENT_GIVEN / CONSENT_WITHDRAWN via
 * AuditEventPublisher → ChainAuditListener, que pseudonimiza o actor).
 *
 * Fecha LGPD Art. 7º/8º (consentimento livre, informado, específico e
 * revogável) / GDPR Art. 6/7.
 *
 * Limitação conhecida: revogar consentimento aqui só registra o fato — não
 * bloqueia login nem suspende a conta. Um "gate" que force reconsentimento
 * (ou congele a conta) fica para uma evolução futura, fora do que este
 * satélite se propôs a fazer.
 */
@Service
@RequiredArgsConstructor
public class ConsentService {

    private final ConsentRecordRepository repository;
    private final ConsentProperties properties;
    private final AuditEventPublisher chainPublisher;

    /**
     * Validação "fail fast" chamada ANTES de criar qualquer coisa em
     * AuthService#register — sem efeito colateral, só rejeita cedo.
     */
    public void validateVersion(String submittedVersion) {
        String required = properties.getCurrentVersion();
        if (submittedVersion == null || submittedVersion.isBlank()) {
            throw new IllegalArgumentException(
                    "Consentimento obrigatório: informe consentVersion=\"" + required + "\"");
        }
        if (!submittedVersion.equals(required)) {
            throw new IllegalArgumentException(
                    "Versão de consentimento desatualizada. Enviado=\"" + submittedVersion
                            + "\", vigente=\"" + required + "\"");
        }
    }

    /**
     * Grava o registro de consentimento e a entry correspondente no Ômega.
     * Chamado só DEPOIS que o usuário já existe de verdade (evita registro
     * de consentimento órfão se o cadastro falhar por outro motivo).
     */
    @Transactional
    public ConsentRecord recordConsent(String username, String version, String ipAddress) {
        ConsentRecord record = ConsentRecord.builder()
                .subjectId(username)
                .version(version)
                .consentedAt(Instant.now())
                .ipAddress(ipAddress)
                .build();
        ConsentRecord saved = repository.save(record);
        chainPublisher.publishConsentEvent(AuditEventType.CONSENT_GIVEN, username, version, ipAddress);
        return saved;
    }

    @Transactional
    public void withdrawConsent(String username, String ipAddress) {
        repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc(username)
                .ifPresent(record -> {
                    record.setRevokedAt(Instant.now());
                    repository.save(record);
                });
        chainPublisher.publishConsentEvent(AuditEventType.CONSENT_WITHDRAWN, username, null, ipAddress);
    }

    /** Usado pela exclusão de conta — esta tabela não é WORM, apaga de verdade. */
    @Transactional
    public void forgetAll(String username) {
        repository.deleteBySubjectId(username);
    }

    public Optional<ConsentRecord> currentConsent(String username) {
        return repository.findFirstBySubjectIdAndRevokedAtIsNullOrderByConsentedAtDesc(username);
    }

    public boolean hasValidCurrentConsent(String username) {
        return currentConsent(username)
                .filter(record -> properties.getCurrentVersion().equals(record.getVersion()))
                .isPresent();
    }
}
