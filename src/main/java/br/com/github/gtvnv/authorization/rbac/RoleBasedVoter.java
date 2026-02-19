package br.com.github.gtvnv.authorization.rbac;

import br.com.github.gtvnv.authorization.voters.AccessVoter;
import br.com.github.gtvnv.domain.model.Subject;
import org.springframework.stereotype.Component;

@Component
public class RoleBasedVoter implements AccessVoter {

    @Override
    public int vote(Subject subject, String resource, String action) {
        // Regra simples: Se for ADMIN, libera tudo
        if (subject.roles().contains("ADMIN")) {
            return ACCESS_GRANTED;
        }

        // Se a rota for administrativa e o cara não for ADMIN
        if (resource.startsWith("/api/admin") && !subject.roles().contains("ADMIN")) {
            return ACCESS_DENIED;
        }

        return ACCESS_ABSTAIN; // Outras regras decidem
    }
}