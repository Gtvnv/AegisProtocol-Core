package br.com.github.gtvnv.network.controller;

import br.com.github.gtvnv.network.domain.NetworkZone;
import br.com.github.gtvnv.network.service.NetworkZoneService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Satélite Network Sentinel — CRUD de zonas confiáveis, ROLE_ADMIN.
 *
 * GET    /api/admin/network/zones     — lista todas (habilitadas ou não)
 * POST   /api/admin/network/zones     — cadastra uma zona nova
 * DELETE /api/admin/network/zones/{id}— remove uma zona
 */
@RestController
@RequestMapping("/api/admin/network/zones")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class NetworkZoneController {

    private final NetworkZoneService zoneService;

    public record CreateZoneRequest(
            @NotBlank String name,
            @NotBlank String cidr,
            String description
    ) {}

    @GetMapping
    public ResponseEntity<List<NetworkZone>> list() {
        return ResponseEntity.ok(zoneService.listAll());
    }

    @PostMapping
    public ResponseEntity<NetworkZone> create(@Valid @RequestBody CreateZoneRequest request) {
        NetworkZone zone = zoneService.createZone(request.name(), request.cidr(), request.description(), currentActor());
        return ResponseEntity.ok(zone);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        zoneService.deleteZone(id, currentActor());
        return ResponseEntity.noContent().build();
    }

    private String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }
}
