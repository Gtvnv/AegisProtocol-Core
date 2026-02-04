package br.com.github.gtvnv.domain.policy;

public record PolicyEvaluationResult(
        Effect effect,
        String reason
) {
    // Um helper para facilitar verificações rápidas no código
    public boolean isAllowed() {
        return effect == Effect.PERMIT;
    }
}