package br.com.github.gtvnv.domain.engine;

import br.com.github.gtvnv.domain.model.AccessContext;
import br.com.github.gtvnv.domain.policy.PolicyEvaluationResult;

public interface AegisPolicyEngine {

    /**
     * Avalia o contexto contra todas as políticas ativas.
     * @param context O snapshot do momento do acesso (Quem, Onde, O que).
     * @return O resultado (PERMIT/DENY) + Motivo (para Audit Trail).
     */
    PolicyEvaluationResult evaluate(AccessContext context);

    /**
     * Recarrega políticas (Hot-swap sem reiniciar a aplicação).
     */
    void refreshPolicies();
}