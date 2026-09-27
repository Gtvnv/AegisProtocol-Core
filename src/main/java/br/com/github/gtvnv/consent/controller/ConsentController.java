package br.com.github.gtvnv.consent.controller;

import br.com.github.gtvnv.consent.config.ConsentProperties;
import br.com.github.gtvnv.consent.service.ConsentService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Satélite Consent Ledger.
 *
 * GET  /auth/consent/current-version — público: qual versão um cliente deve
 *      enviar em RegisterRequest.consentVersion antes de registrar alguém.
 * GET  /auth/consent                 — autenticado: status do consentimento
 *      do próprio titular.
 * POST /auth/consent/withdraw        — autenticado: revoga o consentimento
 *      atual (GDPR Art. 7(3) — tão fácil de retirar quanto de dar).
 */
@RestController
@RequestMapping("/auth/consent")
@RequiredArgsConstructor
public class ConsentController {

    private final ConsentService consentService;
    private final ConsentProperties properties;

    @GetMapping("/current-version")
    public ResponseEntity<Map<String, String>> currentVersion() {
        return ResponseEntity.ok(Map.of(
                "version", properties.getCurrentVersion(),
                "documentUrl", properties.getDocumentUrl() != null ? properties.getDocumentUrl() : ""
        ));
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> myConsentStatus() {
        String username = currentUsername();
        return consentService.currentConsent(username)
                .<ResponseEntity<Map<String, Object>>>map(record -> ResponseEntity.ok(Map.of(
                        "version", record.getVersion(),
                        "consentedAt", record.getConsentedAt().toString(),
                        "currentVersion", properties.getCurrentVersion(),
                        "upToDate", properties.getCurrentVersion().equals(record.getVersion())
                )))
                .orElseGet(() -> ResponseEntity.ok(Map.of(
                        "version", "",
                        "currentVersion", properties.getCurrentVersion(),
                        "upToDate", false
                )));
    }

    @PostMapping("/withdraw")
    public ResponseEntity<Map<String, String>> withdraw(HttpServletRequest request) {
        String username = currentUsername();
        consentService.withdrawConsent(username, request.getRemoteAddr());
        return ResponseEntity.ok(Map.of(
                "message", "Consentimento revogado. A conta permanece ativa; para removê-la, use DELETE /auth/account."
        ));
    }

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("Requisição não autenticada");
        }
        return auth.getName();
    }
}
