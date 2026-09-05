package br.com.github.gtvnv.audit.chain.controller;

import br.com.github.gtvnv.audit.chain.dto.AuditChainEntryDto;
import br.com.github.gtvnv.audit.chain.dto.ChainVerificationReport;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.ChainIntegrityVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * API administrativa de auditoria criptográfica.
 * Todos os endpoints requerem ROLE_ADMIN.
 *
 * GET /api/admin/audit/chain/history/{actor}   — timeline paginada do ator
 * GET /api/admin/audit/chain/verify/{actor}    — verifica integridade da cadeia do ator
 * GET /api/admin/audit/chain/verify            — verifica todos os atores (forense global)
 * GET /api/admin/audit/chain/entry/{id}        — entry individual por ID
 */
@RestController
@RequestMapping("/api/admin/audit/chain")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AuditChainController {

    private final AuditChainRepository repository;
    private final ChainIntegrityVerifier verifier;

    @GetMapping("/history/{actor}")
    public ResponseEntity<Page<AuditChainEntryDto>> history(
            @PathVariable String actor,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "20") int size) {

        Page<AuditChainEntryDto> result = repository
                .findByActorOrderBySequenceNumberDesc(
                        actor,
                        PageRequest.of(page, size, Sort.by("sequenceNumber").descending()))
                .map(AuditChainEntryDto::from);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/verify/{actor}")
    public ResponseEntity<ChainVerificationReport> verifyActor(@PathVariable String actor) {
        return ResponseEntity.ok(verifier.verify(actor));
    }

    @GetMapping("/verify")
    public ResponseEntity<List<ChainVerificationReport>> verifyAll() {
        return ResponseEntity.ok(verifier.verifyAll());
    }

    @GetMapping("/entry/{id}")
    public ResponseEntity<AuditChainEntryDto> entry(@PathVariable String id) {
        return repository.findById(id)
                .map(AuditChainEntryDto::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
