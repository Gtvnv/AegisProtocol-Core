package br.com.github.gtvnv.authentication;

import br.com.github.gtvnv.authentication.dto.LoginRequest;
import br.com.github.gtvnv.authentication.dto.RegisterRequest;
import br.com.github.gtvnv.authentication.dto.TokenResponse;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.token.TokenService;
import br.com.github.gtvnv.crypto.KeyManagerService;
import br.com.github.gtvnv.threat.service.ThreatService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final TokenBlacklistService blacklistService;
    private final TokenService tokenService;
    private final ThreatService threatService;
    private final KeyManagerService keyManagerService;

    // Injeção via construtor
    public AuthController(AuthService authService,
                          TokenBlacklistService blacklistService,
                          TokenService tokenService, ThreatService threatService,
                          KeyManagerService keyManagerService) {
        this.authService = authService;
        this.blacklistService = blacklistService;
        this.tokenService = tokenService;
        this.threatService = threatService;
        this.keyManagerService = keyManagerService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        // 🔥 Proteção Anti-Spam no Registro
        String clientIp = httpRequest.getRemoteAddr();
        threatService.checkLoginAttempts(clientIp); // Usa a mesma lógica ou crie um método específico "checkRegistrationAttempts"

        try {
            TokenResponse response = authService.register(request);
            // Não limpamos o contador no registro para evitar que o cara crie 1 conta a cada segundo.
            // Deixe o rate limit "comer" as tentativas dele se ele for rápido demais.
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.info("Muitas tentativas de registro");
            throw e;
        }
    }

    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> getPublicKey() {
        RSAPublicKey publicKey = keyManagerService.getPublicKey();
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        return ResponseEntity.ok(Map.of(
                "algorithm", "RSA",
                "format", "X.509",
                "key", publicKeyBase64
        ));
    }

    // Correção: Adicionada anotação e tipagem forte no retorno
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                Date expirationDate = tokenService.extractExpiration(token);
                long now = Instant.now().toEpochMilli();
                long expiry = expirationDate.getTime();
                long ttlSeconds = (expiry - now) / 1000;

                if (ttlSeconds > 0) {
                    blacklistService.blacklistToken(token, ttlSeconds);
                }
            } catch (Exception e) {
                // SonarLint Fix: Idempotência.
                // Se o token já expirou, o logout "já aconteceu" tecnicamente.
                // Mantemos 200 OK, mas com uma mensagem clara.
                return ResponseEntity.ok(Map.of("message", "Session already expired or invalid"));
            }
        }

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestHeader("Authorization") String refreshToken) {
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }
}
