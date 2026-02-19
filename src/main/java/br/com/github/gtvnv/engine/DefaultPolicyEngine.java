package br.com.github.gtvnv.engine;

import br.com.github.gtvnv.domain.model.AccessContext;
import br.com.github.gtvnv.domain.policy.*;
import br.com.github.gtvnv.domain.repository.PolicyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
public class DefaultPolicyEngine implements AegisPolicyEngine {

    private final PolicyRepository policyRepository;

    // Agora injetamos o Repositório do banco de dados
    public DefaultPolicyEngine(PolicyRepository policyRepository) {
        this.policyRepository = policyRepository;
    }

    @Override
    public PolicyEvaluationResult evaluate(AccessContext context) {
        log.debug("Iniciando avaliação de política (DB) para: {} -> {}", context.subject().id(), context.resource().identifier());

        // 1. Carrega todas as políticas do Banco e converte para o objeto de Domínio
        // OBS: Em produção com alto tráfego, aqui adicionaríamos Cache (Redis/Caffeine)
        // para não fazer SELECT * em toda requisição.
        List<Policy> activePolicies = policyRepository.findAll().stream()
                .map(entity -> entity.toDomain())
                .toList();

        // 2. Encontra a política aplicável (Target Match)
        Policy applicablePolicy = activePolicies.stream()
                .filter(policy -> isTargetMatch(policy.target(), context))
                .sorted((p1, p2) -> Integer.compare(p2.priority(), p1.priority())) // Maior prioridade primeiro
                .findFirst()
                .orElse(null);

        // 3. Fallback: Se não tem regra explicita, aplica o "Secure-by-default" (DENY)
        if (applicablePolicy == null) {
            log.warn("Nenhuma política encontrada para o recurso. Aplicando Default Deny.");
            return new PolicyEvaluationResult(Effect.DENY, "No matching policy found - Default Deny");
        }

        // 4. Avalia as Condições (ABAC Logic)
        boolean conditionsMet = checkConditions(applicablePolicy.conditions(), context);

        if (conditionsMet) {
            return new PolicyEvaluationResult(applicablePolicy.effect(), "Policy " + applicablePolicy.name() + " satisfied");
        } else {
            return new PolicyEvaluationResult(Effect.DENY, "Policy " + applicablePolicy.name() + " conditions failed");
        }
    }

    @Override
    public void refreshPolicies() {
        // Como estamos lendo direto do banco no método evaluate (findAll),
        // não precisamos recarregar cache manualmente por enquanto.
        log.info("Refresh solicitado - leitura direta do banco ativa.");
    }

    // --- MÉTODOS AUXILIARES (Lógica Pura - Mantidos Iguais) ---

    private boolean isTargetMatch(Target target, AccessContext context) {
        boolean resourceMatch = target.resources().contains("*") ||
                target.resources().contains(context.resource().identifier());

        boolean actionMatch = target.actions().contains("*") ||
                target.actions().contains(context.action());

        return resourceMatch && actionMatch;
    }

    private boolean checkConditions(List<Condition> conditions, AccessContext context) {
        if (conditions == null || conditions.isEmpty()) return true;

        for (Condition condition : conditions) {
            Object contextValue = extractValueFromContext(context, condition.attribute());
            if (!evaluateCondition(contextValue, condition.operator(), condition.value())) {
                log.debug("Condição falhou: {} {} {} (Valor real: {})",
                        condition.attribute(), condition.operator(), condition.value(), contextValue);
                return false;
            }
        }
        return true;
    }

    private Object extractValueFromContext(AccessContext context, String attributePath) {
        if (attributePath.equals("subject.roles")) return context.subject().roles();
        if (attributePath.equals("environment.ip")) return context.environment().ipAddress();

        if (attributePath.startsWith("subject.attributes.")) {
            String key = attributePath.replace("subject.attributes.", "");
            return context.subject().attributes().get(key);
        }

        return null;
    }

    private boolean evaluateCondition(Object actualValue, Operator operator, String requiredValue) {
        if (actualValue == null) return false;

        String actualStr = actualValue.toString();

        return switch (operator) {
            case EQUALS -> actualStr.equals(requiredValue);
            case NOT_EQUALS -> !actualStr.equals(requiredValue);
            case CONTAINS -> actualValue instanceof List<?> list && list.contains(requiredValue);
            case GREATER_THAN ->  compareNumeric(actualStr, requiredValue) > 0;
            case LESS_THAN -> compareNumeric(actualStr, requiredValue) < 0;
            default -> false;
        };
    }

    private double compareNumeric(String v1, String v2) {
        try {
            return Double.compare(Double.parseDouble(v1), Double.parseDouble(v2));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}