package br.com.github.gtvnv.authentication.token;

import br.com.github.gtvnv.config.JwtProperties;
import br.com.github.gtvnv.domain.model.Subject; // Reutilizando nosso modelo
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenService {

    private final JwtProperties jwtProperties;
    private final KeyProvider keyProvider;

    public TokenService(JwtProperties jwtProperties, KeyProvider keyProvider) {
        this.jwtProperties = jwtProperties;
        this.keyProvider = keyProvider;
    }

    public String generateAccessToken(Subject subject) {
        Instant now = Instant.now();
        Instant validity = now.plusSeconds(jwtProperties.getAccessTokenExpiration());

        // Claims Customizadas (Roles, Departamento, etc)
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", subject.roles());
        claims.put("type", "ACCESS"); // Importante diferenciar de Refresh Token

        return Jwts.builder()
                .subject(subject.id())
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(validity))
                .signWith(keyProvider.getKeyPair().getPrivate()) // Assina com Chave Privada
                .compact();
    }

    // O Refresh Token deve ser opaco ou um JWT com menos claims
    public String generateRefreshToken(String userId) {
        Instant now = Instant.now();
        Instant validity = now.plusSeconds(jwtProperties.getRefreshTokenExpiration());

        return Jwts.builder()
                .subject(userId)
                .claim("type", "REFRESH")
                .issuedAt(Date.from(now))
                .expiration(Date.from(validity))
                .signWith(keyProvider.getKeyPair().getPrivate())
                .compact();
    }

    // Validação e Extração de dados
    public Claims validateAndGetClaims(String token) {
        // Se o token for inválido, expirado ou assinatura falsa, o JJWT lança exceção automaticamente
        return Jwts.parser()
                .verifyWith(keyProvider.getKeyPair().getPublic()) // Valida com Chave Pública
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}