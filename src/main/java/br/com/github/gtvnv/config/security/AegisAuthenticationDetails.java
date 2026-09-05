package br.com.github.gtvnv.config.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Carrega as claims do JWT no SecurityContext para que interceptors e voters
 * possam acessar isVerified, jti, tokenType sem re-parsear o token.
 */
public class AegisAuthenticationDetails extends WebAuthenticationDetails {

    private final Claims claims;

    public AegisAuthenticationDetails(HttpServletRequest request, Claims claims) {
        super(request);
        this.claims = claims;
    }

    public boolean isVerified() {
        return Boolean.TRUE.equals(claims.get("verified", Boolean.class));
    }

    public String getTokenType() {
        return claims.get("type", String.class);
    }

    public String getJti() {
        return claims.getId();
    }

    public Claims getClaims() {
        return claims;
    }
}
