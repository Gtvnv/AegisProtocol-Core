package br.com.github.gtvnv.test;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/secret")
public class SecretController {

    @GetMapping
    public ResponseEntity<Map<String, String>> getSecretData(@AuthenticationPrincipal String userId) {
        // Retornando um Map (que vira JSON), o XSS é mitigado automaticamente
        return ResponseEntity.ok(Map.of(
                "message", "ACESSO PERMITIDO! O sistema Aegis está ativo.",
                "userId", userId, // O Jackson vai tratar caracteres especiais aqui
                "status", "SECURE"
        ));
    }
}