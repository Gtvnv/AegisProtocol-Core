package br.com.github.gtvnv.shield.filter;

import br.com.github.gtvnv.config.security.AegisAuthenticationDetails;
import br.com.github.gtvnv.shield.config.ShieldProperties;
import br.com.github.gtvnv.shield.event.ShieldThreatEvent;
import br.com.github.gtvnv.shield.service.IpIntelligenceService;
import br.com.github.gtvnv.shield.service.ShieldRiskScorer;
import br.com.github.gtvnv.shield.service.ShieldRiskScorer.ScoreResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

/**
 * S.H.I.E.L.D. Filter — Secure Host Intelligence for Enterprise Lateral Detection.
 *
 * Executa após JwtAuthenticationFilter. Para requisições autenticadas:
 *  1. Registra acesso no IpIntelligenceService
 *  2. Calcula risk score (fingerprint + lateral movement)
 *  3. Publica ShieldThreatEvent se score >= alertThreshold
 *  4. Bloqueia requisição se score >= blockThreshold (configurável)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ShieldFilter extends OncePerRequestFilter {

    private final ShieldProperties props;
    private final ShieldRiskScorer riskScorer;
    private final IpIntelligenceService ipIntelligence;
    private final ApplicationEventPublisher eventPublisher;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!props.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String ipAddress    = request.getRemoteAddr();
        String resourcePath = request.getRequestURI();
        String userAgent    = request.getHeader("User-Agent");

        // Sempre registra o acesso por IP (incluindo anônimos)
        ipIntelligence.recordAccess(ipAddress, resourcePath);

        // Análise de risco apenas para sessões autenticadas com JTI
        if (auth != null && auth.isAuthenticated()
                && auth.getDetails() instanceof AegisAuthenticationDetails details
                && details.getJti() != null) {

            String jti   = details.getJti();
            String actor = auth.getName();

            ScoreResult result = riskScorer.score(jti, ipAddress, userAgent, resourcePath);

            if (result.level().isAtLeast(props.getAlertThreshold())) {
                boolean blocked = result.level().isAtLeast(props.getBlockThreshold());

                eventPublisher.publishEvent(new ShieldThreatEvent(
                        this, actor, jti, ipAddress, userAgent, resourcePath, result, blocked
                ));

                if (blocked) {
                    log.warn("SHIELD BLOCK: actor={} jti={} ip={} score={} level={}",
                            actor, jti, ipAddress, result.score(), result.level());
                    writeBlockResponse(response, result);
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/auth/")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs")
                || path.equals("/error");
    }

    private void writeBlockResponse(HttpServletResponse response, ScoreResult result) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", 403,
                "error", "Forbidden",
                "message", "S.H.I.E.L.D.: Anomalous behaviour detected. Access denied.",
                "threatLevel", result.level().name()
        );
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
