package br.com.github.gtvnv.retention.controller;

import br.com.github.gtvnv.retention.repository.RetentionCheckpointRepository;
import br.com.github.gtvnv.retention.service.RetentionEngineService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Satélite Retention Engine — operação administrativa, ROLE_ADMIN.
 *
 * POST /api/admin/retention/run                      — dispara um sweep agora (fora do cron)
 * GET  /api/admin/retention/checkpoints               — lista os checkpoints já criados
 * GET  /api/admin/retention/checkpoints/{id}/verify   — confere o checksum do arquivo contra o gravado
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
}
