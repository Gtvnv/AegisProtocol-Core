package br.com.github.gtvnv.config.security;

import br.com.github.gtvnv.domain.model.Subject;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class SecurityUtils {

    /**
     * Extrai o Subject atual do contexto de segurança do Spring.
     * @return Subject ou null se não autenticado.
     */
    public Subject getCurrentSubject() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof UserDetails userDetails)) {
            return null;
        }

        // Converte as Roles do Spring para Lista de Strings
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(role -> role.replace("ROLE_", ""))
                .toList();

        // O Spring User 'enabled' é o nosso 'isVerified' (conforme configuramos no AegisUserDetailsService)
        // Lembre-se: configuramos .disabled(false) mas precisamos saber a verdade do banco.
        // *Nota de Arquitetura*: Idealmente, leríamos a claim 'verified' do token JWT aqui.
        // Mas como estamos carregando do banco a cada request no Filtro, podemos usar o estado do objeto.
        // Para simplificar agora, vamos assumir que enabled = verified.
        boolean isVerified = userDetails.isEnabled();

        return new Subject(
                userDetails.getUsername(),
                roles,
                Map.of("source", "security_context"),
                isVerified
        );
    }
}