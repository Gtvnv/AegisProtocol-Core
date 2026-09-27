package br.com.github.gtvnv.incident.controller;

import br.com.github.gtvnv.incident.domain.IncidentStatus;
import br.com.github.gtvnv.incident.domain.SecurityIncident;
import br.com.github.gtvnv.incident.repository.SecurityIncidentRepository;
import br.com.github.gtvnv.incident.service.IncidentOrchestratorService;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * Satélite Incident Response Orchestrator — operação administrativa, ROLE_ADMIN.
 *
 * GET  /api/admin/incidents                    — lista (opcionalmente filtrada por status)
 * GET  /api/admin/incidents/{id}                — detalhe
 * POST /api/admin/incidents/{id}/acknowledge    — reconhece (some com o SLA de acknowledge)
 * POST /api/admin/incidents/{id}/notify         — marca titular + ANPD como notificados
 * POST /api/admin/incidents/{id}/resolve        — encerra com nota de resolução
 */
@RestController
@RequestMapping("/api/admin/incidents")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class IncidentController {

    private final SecurityIncidentRepository repository;
    private final IncidentOrchestratorService orchestrator;

    public record ResolveRequest(@NotBlank String notes) {}

    @GetMapping
    public ResponseEntity<List<SecurityIncident>> list(@RequestParam(required = false) IncidentStatus status) {
        List<SecurityIncident> incidents = status != null
                ? repository.findByStatusOrderByOpenedAtDesc(status)
                : repository.findAllByOrderByOpenedAtDesc();
        return ResponseEntity.ok(incidents);
    }

    @GetMapping("/{id}")
    public ResponseEntity<SecurityIncident> get(@PathVariable UUID id) {
        return repository.findById(id)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new NoSuchElementException("Incidente não encontrado: " + id));
    }

    @PostMapping("/{id}/acknowledge")
    public ResponseEntity<SecurityIncident> acknowledge(@PathVariable UUID id) {
        return ResponseEntity.ok(orchestrator.acknowledge(id, currentActor()));
    }

    @PostMapping("/{id}/notify")
    public ResponseEntity<SecurityIncident> notify(@PathVariable UUID id) {
        return ResponseEntity.ok(orchestrator.notify(id, currentActor()));
    }

    @PostMapping("/{id}/resolve")
    public ResponseEntity<SecurityIncident> resolve(@PathVariable UUID id, @jakarta.validation.Valid @RequestBody ResolveRequest request) {
        return ResponseEntity.ok(orchestrator.resolve(id, currentActor(), request.notes()));
    }

    private String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }
}
