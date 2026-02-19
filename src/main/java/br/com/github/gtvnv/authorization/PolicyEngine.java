package br.com.github.gtvnv.authorization;

import br.com.github.gtvnv.authorization.voters.AccessVoter;
import br.com.github.gtvnv.domain.model.Subject;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PolicyEngine {

    private final List<AccessVoter> voters; // O Spring injeta todos os componentes automaticamente

    public boolean authorize(Subject subject, String resource, String action) {
        int grant = 0;
        int deny = 0;

        for (AccessVoter voter : voters) {
            int result = voter.vote(subject, resource, action);
            if (result == AccessVoter.ACCESS_DENIED) {
                return false; // Veto absoluto (Deny Override)
            }
            if (result == AccessVoter.ACCESS_GRANTED) {
                grant++;
            }
        }

        // Política: Pelo menos um deve aprovar (Affirmative Based)
        return grant > 0;
    }
}