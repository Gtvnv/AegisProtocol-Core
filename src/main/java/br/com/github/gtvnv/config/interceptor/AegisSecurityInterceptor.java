package br.com.github.gtvnv.config.interceptor;

import br.com.github.gtvnv.audit.event.SecurityAuditEvent;
import br.com.github.gtvnv.config.security.AegisAuthenticationDetails;
import br.com.github.gtvnv.domain.model.AccessContext;
import br.com.github.gtvnv.domain.model.Environment;
import br.com.github.gtvnv.domain.model.Resource;
import br.com.github.gtvnv.domain.model.Subject;
import br.com.github.gtvnv.domain.policy.PolicyEvaluationResult;
import br.com.github.gtvnv.engine.AegisPolicyEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class AegisSecurityInterceptor implements HandlerInterceptor {

    private final AegisPolicyEngine policyEngine;
    private final ObjectMapper objectMapper;
    private final ApplicationEventPublisher eventPublisher; // 1. Nova dependência

    public AegisSecurityInterceptor(AegisPolicyEngine policyEngine,
                                    ObjectMapper objectMapper,
                                    ApplicationEventPublisher eventPublisher) {
        this.policyEngine = policyEngine;
        this.objectMapper = objectMapper;
        this.eventPublisher = eventPublisher;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        // 1. Ignora rotas públicas
        if (request.getRequestURI().startsWith("/auth") || request.getRequestURI().startsWith("/error")) {
            return true;
        }

        // 2. Coleta quem é o usuário
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unidentified Subject");
            return false;
        }

        // 3. Monta o Contexto
        AccessContext context = buildContext(request, auth);

        // 4. O Grande Momento: Chama a Engine
        PolicyEvaluationResult result = policyEngine.evaluate(context);

        // 5. 🔥 AUDITORIA (Dispara o evento para o Listener salvar no banco)
        // Isso acontece INDEPENDENTE de ser permitido ou negado
        eventPublisher.publishEvent(new SecurityAuditEvent(
                this,
                context,
                result.isAllowed(),
                result.reason()
        ));

        // 6. Tratamento da Decisão
        if (!result.isAllowed()) {
            // Log no console para debug imediato
            log.warn("⛔ ACESSO NEGADO PELO AEGIS: {} | User: {} | IP: {}",
                    result.reason(), auth.getName(), request.getRemoteAddr());

            // Resposta JSON segura para o cliente
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            Map<String, Object> errorResponse = Map.of(
                    "timestamp", Instant.now().toString(),
                    "status", 403,
                    "error", "Forbidden",
                    "message", "Aegis Security Block: Access denied by policy."
            );

            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
            return false; // Bloqueia
        }

        log.info("✅ ACESSO APROVADO PELO AEGIS: {}", result.reason());
        return true; // Deixa passar
    }

    private AccessContext buildContext(HttpServletRequest request, Authentication auth) {
        List<String> roles = new ArrayList<>();
        for (GrantedAuthority a : auth.getAuthorities()) {
            roles.add(a.getAuthority().replace("ROLE_", ""));
        }

        // Lê isVerified diretamente das claims JWT — evita o bug do MVP onde
        // o construtor de 3 args defaultava isVerified=false para todos os usuários.
        boolean isVerified = false;
        if (auth.getDetails() instanceof AegisAuthenticationDetails details) {
            isVerified = details.isVerified();
        }

        Subject subject = new Subject(auth.getName(), roles, Collections.emptyMap(), isVerified);
        Resource resource = new Resource(request.getRequestURI(), "API_ENDPOINT", "HIGH");
        Environment env = new Environment(request.getRemoteAddr(), Instant.now(), 0);

        return new AccessContext(subject, resource, request.getMethod(), env);
    }
}