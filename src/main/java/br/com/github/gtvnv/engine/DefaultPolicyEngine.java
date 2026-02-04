package br.com.github.gtvnv.engine;

import br.com.github.gtvnv.domain.policy.Policy;
import br.com.github.gtvnv.domain.model.AccessContext;
import br.com.github.gtvnv.domain.policy.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import br.com.github.gtvnv.domain.engine.AegisPolicyEngine;

import java.util.List;

@Slf4j
@Service
public class DefaultPolicyEngine implements AegisPolicyEngine {

    // Simulação de um repositório (Em prod, isso viria do Redis/Banco com Caching)
    private final List<Policy> loadedPolicies;

    public DefaultPolicyEngine(List<Policy> loadedPolicies) {
        this.loadedPolicies = loadedPolicies;
    }

    @Override
    public PolicyEvaluationResult evaluate(AccessContext context) {
        log.debug("Iniciando avaliação de política para: {} -> {}", context.subject().id(), context.resource().identifier());

        // 1. Encontra a política aplicável (Target Match)
        // Em um sistema real, isso deve ser otimizado (ex: Trie ou Hash Map) e não linear
        Policy applicablePolicy = loadedPolicies.stream()
                .filter(policy -> isTargetMatch(policy.target(), context))
                .sorted((p1, p2) -> Integer.compare(p2.priority(), p1.priority())) // Maior prioridade primeiro
                .findFirst()
                .orElse(null);

        // 2. Fallback: Se não tem regra explicita, aplica o "Secure-by-default" (DENY)
        if (applicablePolicy == null) {
            log.warn("Nenhuma política encontrada para o recurso. Aplicando Default Deny.");
            return new PolicyEvaluationResult(Effect.DENY, "No matching policy found - Default Deny");
        }

        // 3. Avalia as Condições (ABAC Logic)
        boolean conditionsMet = checkConditions(applicablePolicy.conditions(), context);

        if (conditionsMet) {
            // Se as condições baterem, retorna o efeito da política (geralmente PERMIT, mas pode ser uma regra de DENY explícito)
            return new PolicyEvaluationResult(applicablePolicy.effect(), "Policy " + applicablePolicy.id() + " satisfied");
        } else {
            return new PolicyEvaluationResult(Effect.DENY, "Policy " + applicablePolicy.id() + " conditions failed");
        }
    }

    @Override
    public void refreshPolicies() {

    }

    private boolean isTargetMatch(Target target, AccessContext context) {
        // Verifica se o recurso atual está na lista de recursos da política
        // Suporta wildcard básico "*"
        boolean resourceMatch = target.resources().contains("*") ||
                target.resources().contains(context.resource().identifier());

        boolean actionMatch = target.actions().contains("*") ||
                target.actions().contains(context.action());

        return resourceMatch && actionMatch;
    }

    private boolean checkConditions(List<Condition> conditions, AccessContext context) {
        if (conditions == null || conditions.isEmpty()) return true; // Sem condições = Acesso livre dentro do Target

        for (Condition condition : conditions) {
            Object contextValue = extractValueFromContext(context, condition.attribute());
            if (!evaluateCondition(contextValue, condition.operator(), condition.value())) {
                log.debug("Condição falhou: {} {} {} (Valor real: {})",
                        condition.attribute(), condition.operator(), condition.value(), contextValue);
                return false; // Bastou uma falhar para negar (Lógica AND)
            }
        }
        return true;
    }

    // Extrai o valor dinamicamente. Ex: "subject.attributes.department"
    private Object extractValueFromContext(AccessContext context, String attributePath) {
        // Implementação simplificada.
        // Aqui você mapearia "subject.roles" -> context.subject().roles()
        // "environment.ip" -> context.environment().ipAddress()

        if (attributePath.equals("subject.roles")) return context.subject().roles();
        if (attributePath.equals("environment.ip")) return context.environment().ipAddress();

        // Busca genérica nos atributos extras
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
            return 0; // Ou lançar erro de configuração
        }
    }
}