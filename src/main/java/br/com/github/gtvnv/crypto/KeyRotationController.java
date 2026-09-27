package br.com.github.gtvnv.crypto;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Operação administrativa do satélite KMS/Secrets: rotaciona o par de chaves RSA
 * usado para assinar os JWTs. Protegido por hasRole("ADMIN") via SecurityConfig
 * (matcher "/api/admin/**").
 */
@RestController
@RequestMapping("/api/admin/keys")
@RequiredArgsConstructor
public class KeyRotationController {

    private final KeyManagerService keyManagerService;
    private final AuditEventPublisher chainPublisher;

    public record KeyRotationResponse(String previousKid, String newKid, java.util.List<String> retainedKids) {}

    @PostMapping("/rotate")
    public ResponseEntity<KeyRotationResponse> rotate(HttpServletRequest request) {
        KeyManagerService.RotationResult result = keyManagerService.rotate();

        String actor = resolveActor();
        chainPublisher.publishKeyEvent(AuditEventType.SIGNING_KEY_ROTATED, actor,
                result.newKid(), request.getRemoteAddr());

        return ResponseEntity.ok(new KeyRotationResponse(
                result.previousKid(), result.newKid(), result.retainedKids()));
    }

    private String resolveActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }
}
