package br.com.github.gtvnv.policy.controller;

import br.com.github.gtvnv.domain.entity.PolicyEntity;
import br.com.github.gtvnv.policy.dto.PolicyRequest;
import br.com.github.gtvnv.policy.service.PolicyAuditService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Satélite Policy Audit — CRUD administrativo de políticas ABAC/RBAC,
 * ROLE_ADMIN. Antes deste satélite não existia API nenhuma pra isso
 * (só seed inicial ou acesso direto ao banco) — agora toda mutação
 * também vira entry no Ômega (ver PolicyAuditService).
 */
@RestController
@RequestMapping("/api/admin/policies")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class PolicyController {

    private final PolicyAuditService service;

    @GetMapping
    public ResponseEntity<List<PolicyEntity>> list() {
        return ResponseEntity.ok(service.listAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<PolicyEntity> get(@PathVariable UUID id) {
        return ResponseEntity.ok(service.getOrThrow(id));
    }

    @PostMapping
    public ResponseEntity<PolicyEntity> create(@Valid @RequestBody PolicyRequest request) {
        return ResponseEntity.ok(service.create(request, currentActor()));
    }

    @PutMapping("/{id}")
    public ResponseEntity<PolicyEntity> update(@PathVariable UUID id, @Valid @RequestBody PolicyRequest request) {
        return ResponseEntity.ok(service.update(id, request, currentActor()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        service.delete(id, currentActor());
        return ResponseEntity.noContent().build();
    }

    private String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }
}
