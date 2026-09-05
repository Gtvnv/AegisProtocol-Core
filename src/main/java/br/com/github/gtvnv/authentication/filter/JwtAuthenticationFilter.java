package br.com.github.gtvnv.authentication.filter;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.authentication.service.AegisUserDetailsService;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.token.TokenService;
import br.com.github.gtvnv.config.security.AegisAuthenticationDetails;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final AegisUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService;
    private final AuditEventPublisher chainPublisher;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        // Fast-fail: token revogado antes de qualquer parse custoso
        if (blacklistService.isTokenBlacklisted(jwt)) {
            chainPublisher.publishTokenEvent(AuditEventType.TOKEN_BLACKLIST_VIOLATION,
                    "ANONYMOUS", null, request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Token revoked or expired\"}");
            return;
        }

        final Claims claims;
        try {
            claims = tokenService.validateAndGetClaims(jwt);
        } catch (Exception e) {
            // Token inválido ou expirado: segue sem autenticar (Security retorna 401/403)
            filterChain.doFilter(request, response);
            return;
        }

        // Rejeita Refresh Tokens usados como Access Tokens (vuln crítica do MVP)
        if (!"ACCESS".equals(claims.get("type", String.class))) {
            chainPublisher.publishTokenEvent(AuditEventType.REFRESH_TOKEN_USED_AS_ACCESS,
                    claims.getSubject(), claims.getId(), request.getRemoteAddr());
            filterChain.doFilter(request, response);
            return;
        }

        final String userEmail = claims.getSubject();

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (tokenService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                // Propaga claims (isVerified, jti, type) pelo SecurityContext
                authToken.setDetails(new AegisAuthenticationDetails(request, claims));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
