package br.com.github.gtvnv.network.filter;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.network.config.NetworkProperties;
import br.com.github.gtvnv.network.service.NetworkZoneService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Satélite Network Sentinel — extensão do Zero Trust do S.H.I.E.L.D. para o
 * perímetro de rede. Roda ANTES da autenticação: uma origem de fora de
 * qualquer zona confiável nem chega a gastar ciclo com JWT/ABAC nos
 * caminhos protegidos (default: /api/admin/**). Fecha ISO A.8.20.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NetworkSentinelFilter extends OncePerRequestFilter {

    private final NetworkProperties properties;
    private final NetworkZoneService zoneService;
    private final AuditEventPublisher chainPublisher;
    private final ObjectMapper objectMapper;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!properties.isSentinelEnabled() || !isProtectedPath(request.getRequestURI())) {
            chain.doFilter(request, response);
            return;
        }

        String ip = request.getRemoteAddr();
        if (zoneService.isSourceTrusted(ip)) {
            chain.doFilter(request, response);
            return;
        }

        String actor = resolveActor();
        String path = request.getRequestURI();

        if (properties.isBlockOnUntrustedSource()) {
            chainPublisher.publishNetworkEvent(AuditEventType.NETWORK_UNTRUSTED_SOURCE_BLOCKED,
                    actor, ip, path, "Blocked: source outside all trusted network zones");
            log.warn("NETWORK SENTINEL BLOCK: actor={} ip={} path={}", actor, ip, path);
            writeBlockResponse(response, ip);
            return;
        }

        chainPublisher.publishNetworkEvent(AuditEventType.NETWORK_UNTRUSTED_SOURCE_ALERTED,
                actor, ip, path, "Alert: source outside all trusted network zones (not blocked)");
        log.warn("NETWORK SENTINEL ALERT: actor={} ip={} path={}", actor, ip, path);
        chain.doFilter(request, response);
    }

    private boolean isProtectedPath(String uri) {
        List<String> patterns = properties.getProtectedPathPatterns();
        return patterns != null && patterns.stream().anyMatch(pattern -> pathMatcher.match(pattern, uri));
    }

    private String resolveActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return (auth != null && auth.isAuthenticated()) ? auth.getName() : "ANONYMOUS";
    }

    private void writeBlockResponse(HttpServletResponse response, String ip) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", 403,
                "error", "Forbidden",
                "message", "Network Sentinel: source IP is outside all trusted network zones."
        );
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
