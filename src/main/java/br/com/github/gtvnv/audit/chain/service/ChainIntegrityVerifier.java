package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.dto.ChainVerificationReport;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Verifica matematicamente a integridade da cadeia de auditoria.
 *
 * Para cada entry:
 *  1. Recalcula expectedHash via AuditHashEngine usando os campos armazenados
 *  2. Compara com selfHash persistido
 *  3. Verifica que previousHash == selfHash do entry anterior
 *
 * Qualquer divergência indica adulteração e retorna o ID do primeiro entry quebrado.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ChainIntegrityVerifier {

    private static final String GENESIS = "GENESIS";

    private final AuditChainRepository repository;
    private final AuditHashEngine hashEngine;

    @Transactional(readOnly = true)
    public ChainVerificationReport verify(String actor) {
        List<AuditChainEntry> chain = repository.findByActorOrderBySequenceNumberAsc(actor);

        if (chain.isEmpty()) {
            return ChainVerificationReport.valid(actor, 0);
        }

        String expectedPreviousHash = GENESIS;

        for (AuditChainEntry entry : chain) {
            // Verifica que o previousHash armazenado corresponde ao hash do entry anterior
            if (!expectedPreviousHash.equals(entry.getPreviousHash())) {
                log.warn("ChainVerifier: previousHash inválido entry={} actor={}", entry.getId(), actor);
                return ChainVerificationReport.broken(actor, chain.size(), entry.getId());
            }

            // Recalcula o hash e compara com o armazenado
            String recomputed = hashEngine.compute(
                    entry.getId(),
                    entry.getTimestamp(),
                    entry.getActor(),
                    entry.getEventType(),
                    entry.getPayloadJson() != null ? entry.getPayloadJson() : "{}",
                    entry.getPreviousHash()
            );

            if (!recomputed.equals(entry.getSelfHash())) {
                log.warn("ChainVerifier: selfHash adulterado entry={} actor={}", entry.getId(), actor);
                return ChainVerificationReport.broken(actor, chain.size(), entry.getId());
            }

            expectedPreviousHash = entry.getSelfHash();
        }

        return ChainVerificationReport.valid(actor, chain.size());
    }

    @Transactional(readOnly = true)
    public List<ChainVerificationReport> verifyAll() {
        List<String> actors = repository.findAllDistinctActors();
        return actors.stream()
                .map(this::verify)
                .toList();
    }
}
