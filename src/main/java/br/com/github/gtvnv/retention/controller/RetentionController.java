package br.com.github.gtvnv.retention.controller;

import br.com.github.gtvnv.retention.domain.RetentionCheckpoint;
import br.com.github.gtvnv.retention.repository.RetentionCheckpointRepository;
import br.com.github.gtvnv.retention.service.RetentionEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Satélite Retention Engine — operação administrativa, ROLE_ADMIN.
 *
 * POST /api/admin/retention/run                            — dispara um sweep agora (fora do cron)
 * GET  /api/admin/retention/checkpoints                     — lista os checkpoints já criados
 * GET  /api/admin/retention/checkpoints/{id}/verify         — confere o checksum do arquivo contra o gravado
 * POST /api/admin/retention/checkpoints/{id}/mark-purged    — registra que o purge físico manual (ver
 *      docs/retention-purge-runbook.md) já foi executado por um DBA — não apaga nada, só audita o fato
 */
@RestController
@RequestMapping("/api/admin/retention")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class RetentionController {

    private final RetentionEngineService retentionEngine;
    private final RetentionCheckpointRepository checkpointRepository;

    @PostMapping("/run")
    public ResponseEntity<RetentionEngineService.SweepResult> run() {
        return ResponseEntity.ok(retentionEngine.runSweep());
    }

    @GetMapping("/checkpoints")
    public ResponseEntity<?> checkpoints() {
        return ResponseEntity.ok(checkpointRepository.findAllByOrderByCreatedAtDesc());
    }

    @GetMapping("/checkpoints/{id}/verify")
    public ResponseEntity<RetentionEngineService.VerificationResult> verify(@PathVariable UUID id) {
        return ResponseEntity.ok(retentionEngine.verify(id));
    }

    @PostMapping("/checkpoints/{id}/mark-purged")
    public ResponseEntity<RetentionCheckpoint> markPurged(@PathVariable UUID id) {
        return ResponseEntity.ok(retentionEngine.markPurged(id, currentActor()));
    }

    private String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }
}
