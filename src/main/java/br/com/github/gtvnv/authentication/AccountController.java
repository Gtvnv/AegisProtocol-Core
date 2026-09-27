package br.com.github.gtvnv.authentication;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.dto.AuditChainEntryDto;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.token.TokenService;
import br.com.github.gtvnv.consent.service.ConsentService;
import br.com.github.gtvnv.domain.entity.UserEntity;
import br.com.github.gtvnv.domain.repository.UserRepository;
import br.com.github.gtvnv.privacy.service.PrivacyGateService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Satélite IAM Self-Service: o titular administra a própria conta.
 * Protegido implicitamente pelo SecurityConfig (anyRequest().authenticated() —
 * "/auth/account/**" não está na lista de rotas públicas).
 *
 * Fecha LGPD Art. 18 (livre acesso, portabilidade e eliminação) / GDPR Art. 15 e 17.
 */
@Slf4j
@RestController
@RequestMapping("/auth/account")
@RequiredArgsConstructor
public class AccountController {

    private final UserRepository userRepository;
    private final PrivacyGateService privacyGate;
    private final AuditChainService chainService;
    private final AuditChainRepository auditChainRepository;
    private final TokenBlacklistService blacklistService;
    private final TokenService tokenService;
    private final ConsentService consentService;

    @GetMapping("/export")
    public ResponseEntity<Map<String, Object>> exportAccount() {
        String username = currentUsername();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Usuário autenticado não encontrado: " + username));

        // get-or-create é seguro aqui: só estamos LENDO a trilha do titular,
        // não apaga nem cria vínculo novo além do que auditorias já teriam criado.
        String pseudonym = privacyGate.pseudonymize(username);
        var auditTrail = auditChainRepository.findByActorOrderBySequenceNumberAsc(pseudonym).stream()
                .map(AuditChainEntryDto::from)
                .toList();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("username", user.getUsername());
        data.put("email", user.getEmail());
        data.put("roles", user.getRoles());
        data.put("emailVerified", user.isEnabled());
        data.put("consent", consentService.currentConsent(username)
                .map(c -> Map.of("version", c.getVersion(), "consentedAt", c.getConsentedAt().toString()))
                .orElse(Map.of()));
        data.put("auditTrailEntryCount", auditTrail.size());
        data.put("auditTrail", auditTrail);
        data.put("exportedAt", Instant.now().toString());

        return ResponseEntity.ok(data);
    }

    /**
     * Apaga a conta e crypto-shreda o vínculo de identidade do titular no Ômega.
     *
     * Ordem importa e é intencionalmente SÍNCRONA (chama AuditChainService
     * direto, não via ApplicationEventPublisher — que é @Async e não garantiria
     * a ordem): grava o evento final ENQUANTO a chave ainda existe, só então
     * destrói a chave. Entries já gravadas continuam com hash válido; só
     * deixam de poder ser re-associadas ao titular a partir daqui.
     */
    @DeleteMapping
    public ResponseEntity<Map<String, String>> deleteAccount(HttpServletRequest request) {
        String username = currentUsername();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Usuário autenticado não encontrado: " + username));

        String pseudonym = privacyGate.pseudonymize(username);
        chainService.append(
                AuditEventType.ACCOUNT_DELETED,
                pseudonym,
                null,
                request.getRemoteAddr(),
                request.getHeader("User-Agent"),
                null,
                "Account deletion requested by subject",
                Map.of("eventCategory", "AUTH")
        );

        privacyGate.forget(username);
        consentService.forgetAll(username); // consent_records não é WORM — apaga de verdade
        userRepository.delete(user);
        blacklistCurrentToken(request);

        log.warn("IAM Self-Service: conta '{}' removida e vínculo de identidade destruído.", username);
        return ResponseEntity.ok(Map.of("message", "Conta removida e vínculo de identidade destruído"));
    }

    private void blacklistCurrentToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        try {
            String token = authHeader.substring(7);
            Date expiration = tokenService.extractExpiration(token);
            long ttlSeconds = (expiration.getTime() - Instant.now().toEpochMilli()) / 1000;
            if (ttlSeconds > 0) {
                blacklistService.blacklistToken(token, ttlSeconds);
            }
        } catch (Exception e) {
            // Token já inválido/expirado — a conta já foi removida de qualquer forma.
            log.debug("AccountController: não foi possível revogar o token da própria requisição: {}", e.getMessage());
        }
    }

    private String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("Requisição não autenticada");
        }
        return auth.getName();
    }
}
