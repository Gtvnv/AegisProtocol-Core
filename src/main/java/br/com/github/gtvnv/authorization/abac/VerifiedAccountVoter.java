package br.com.github.gtvnv.authorization.abac;

import br.com.github.gtvnv.authorization.voters.AccessVoter;
import br.com.github.gtvnv.domain.model.Subject;
import org.springframework.stereotype.Component;

@Component
public class VerifiedAccountVoter implements AccessVoter {

    @Override
    public int vote(Subject subject, String resource, String action) {
        // Regra de Negócio Crítica:
        // Recursos sensíveis exigem verificação de e-mail
        if ((resource.startsWith("/api/financeiro") || resource.startsWith("/api/transacoes")) && !subject.isVerified()) {
                return ACCESS_DENIED; // Soft Lock ativado!
            }
        return ACCESS_ABSTAIN;
    }
}