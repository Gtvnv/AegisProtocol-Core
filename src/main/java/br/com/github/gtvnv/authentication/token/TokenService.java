package br.com.github.gtvnv.authentication.token;

import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.crypto.KeyManagerService;
import br.com.github.gtvnv.domain.model.Subject; // Importe o Subject
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class TokenService {

    private final JwtProperties jwtProperties;
    private final KeyManagerService keyManagerService;

    public TokenService(JwtProperties jwtProperties, KeyManagerService keyManagerService) {
        this.jwtProperties = jwtProperties;
        this.keyManagerService = keyManagerService;
    }

    public String generateAccessToken(Subject subject) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("roles", subject.roles());
        extraClaims.put("type", "ACCESS");
        extraClaims.put("verified", subject.isVerified());

        // Usa o tempo definido no application.yml via JwtProperties
        return buildToken(subject.id(), extraClaims, jwtProperties.getAccessTokenExpiration());
    }

    public String generateRefreshToken(String username) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("type", "REFRESH");

        return buildToken(username, extraClaims, jwtProperties.getRefreshTokenExpiration());
    }

    private String buildToken(String subject, Map<String, Object> extraClaims, long expirationSeconds) {
        Instant now = Instant.now();
        Instant validity = now.plusSeconds(expirationSeconds);

        return Jwts.builder()
                .subject(subject)
                .claims(extraClaims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(validity))
                // 🔥 Usa o KeyManagerService
                .signWith(keyManagerService.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }
    

    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
                // 🔥 Usa o KeyManagerService
                .verifyWith(keyManagerService.getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // --- Métodos de Extração e Validação (Mantidos) ---

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = validateAndGetClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean isRefreshToken(String token) {
        try {
            String type = extractClaim(token, claims -> claims.get("type", String.class));
            return "REFRESH".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

}