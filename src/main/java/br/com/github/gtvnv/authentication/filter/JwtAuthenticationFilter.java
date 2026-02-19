package br.com.github.gtvnv.authentication.filter;

import br.com.github.gtvnv.authentication.service.AegisUserDetailsService;
import br.com.github.gtvnv.authentication.revocation.TokenBlacklistService;
import br.com.github.gtvnv.authentication.token.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final AegisUserDetailsService userDetailsService;
    private final TokenBlacklistService blacklistService; // Injeção do novo serviço

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // 1. Verifica se o header existe e começa com Bearer
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);

        // 2. 🔥 CHECKLIST DE REVOGAÇÃO (FAIL-FAST)
        // Verificamos o Redis ANTES de gastar recursos validando assinatura ou buscando no banco.
        if (blacklistService.isTokenBlacklisted(jwt)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Token revoked or expired (Blacklisted)\"}");
            return; // ⛔ Aborta a requisição aqui mesmo
        }

        // 3. Extrai o usuário do token
        try {
            userEmail = tokenService.extractUsername(jwt);
        } catch (Exception e) {
            // Se o token for inválido/expirado, o parser do JWT lança exceção.
            // Apenas seguimos o fluxo (o contexto ficará vazio e retornará 403 depois).
            filterChain.doFilter(request, response);
            return;
        }

        // 4. Fluxo de Autenticação Padrão
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Busca o usuário no banco
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Valida a assinatura e se pertence ao usuário
            if (tokenService.isTokenValid(jwt, userDetails)) {

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Coloca o usuário autenticado no contexto para o resto da aplicação
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}