package br.com.github.gtvnv.authorization.voters;

import br.com.github.gtvnv.domain.model.Subject;

public interface AccessVoter {
    // Retorna: 1 (ACCESS_GRANTED), -1 (ACCESS_DENIED), 0 (ACCESS_ABSTAIN)
    int vote(Subject subject, String resource, String action);

    // Constantes para facilitar
    int ACCESS_GRANTED = 1;
    int ACCESS_DENIED = -1;
    int ACCESS_ABSTAIN = 0;
}