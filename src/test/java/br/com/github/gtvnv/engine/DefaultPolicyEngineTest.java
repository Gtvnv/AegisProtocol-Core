package br.com.github.gtvnv.engine;

import br.com.github.gtvnv.domain.entity.PolicyEntity;
import br.com.github.gtvnv.domain.model.AccessContext;
import br.com.github.gtvnv.domain.model.Environment;
import br.com.github.gtvnv.domain.model.Resource;
import br.com.github.gtvnv.domain.model.Subject;
import br.com.github.gtvnv.domain.policy.*;
import br.com.github.gtvnv.domain.repository.PolicyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Testes adversariais do DefaultPolicyEngine (motor ABAC).
 *
 * Cobre: secure-by-default (nenhuma política → DENY), wildcard de resource/action,
 * todos os Operators (EQUALS, NOT_EQUALS, CONTAINS, GREATER_THAN, LESS_THAN),
 * prioridade entre políticas conflitantes, condição falha → DENY mesmo em política PERMIT.
 */
@ExtendWith(MockitoExtension.class)
class DefaultPolicyEngineTest {

    @Mock private PolicyRepository policyRepository;
    @InjectMocks private DefaultPolicyEngine engine;

    // -----------------------------------------------------------------------
    // Helpers de construção de objetos de domínio
    // -----------------------------------------------------------------------

    private PolicyEntity policy(String name, Effect effect, int priority,
                                 Target target, List<Condition> conditions) {
        return PolicyEntity.builder()
            .id(UUID.randomUUID())
            .name(name)
            .effect(effect)
            .priority(priority)
            .target(target)
            .conditions(conditions)
            .build();
    }

    private Target target(List<String> resources, List<String> actions) {
        return new Target(resources, actions);
    }

    private Condition cond(String attr, Operator op, String value) {
        return new Condition(attr, op, value);
    }

    private AccessContext context(String actor, List<String> roles, String resource, String action) {
        Subject  subject = new Subject(actor, roles, Map.of(), true);
        Resource res     = new Resource(resource, "API", "PUBLIC");
        Environment env  = new Environment("127.0.0.1", Instant.now(), 0);
        return new AccessContext(subject, res, action, env);
    }

    private AccessContext contextWithAttributes(String actor, List<String> roles,
                                                 Map<String, Object> attrs,
                                                 String resource, String action) {
        Subject  subject = new Subject(actor, roles, attrs, true);
        Resource res     = new Resource(resource, "API", "PUBLIC");
        Environment env  = new Environment("127.0.0.1", Instant.now(), 0);
        return new AccessContext(subject, res, action, env);
    }

    // -----------------------------------------------------------------------
    // Secure-by-default
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sem nenhuma política cadastrada → DENY (secure-by-default)")
    void evaluate_NoPolicies_DefaultDeny() {
        when(policyRepository.findAll()).thenReturn(List.of());

        PolicyEvaluationResult result = engine.evaluate(context("alice", List.of("USER"), "/api/secret", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
        assertThat(result.reason()).containsIgnoringCase("No matching policy");
    }

    @Test
    @DisplayName("Política existente mas para outro recurso → DENY (nenhum match)")
    void evaluate_PolicyForDifferentResource_DefaultDeny() {
        PolicyEntity p = policy("other-resource-policy", Effect.PERMIT, 1,
            target(List.of("/api/other"), List.of("GET")), List.of());
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(context("alice", List.of("USER"), "/api/secret", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
    }

    // -----------------------------------------------------------------------
    // Wildcard de resource e action
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Wildcard '*' em resources cobre qualquer recurso")
    void evaluate_WildcardResource_MatchesAnyResource() {
        PolicyEntity p = policy("allow-all-resources", Effect.PERMIT, 1,
            target(List.of("*"), List.of("GET")), List.of());
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(context("alice", List.of(), "/api/anything/here", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Wildcard '*' em actions cobre qualquer ação")
    void evaluate_WildcardAction_MatchesAnyAction() {
        PolicyEntity p = policy("allow-all-actions", Effect.PERMIT, 1,
            target(List.of("/api/resource"), List.of("*")), List.of());
        when(policyRepository.findAll()).thenReturn(List.of(p));

        assertThat(engine.evaluate(context("alice", List.of(), "/api/resource", "DELETE")).effect())
            .isEqualTo(Effect.PERMIT);
        assertThat(engine.evaluate(context("alice", List.of(), "/api/resource", "POST")).effect())
            .isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Wildcards em resource E action combinados: match total")
    void evaluate_BothWildcards_MatchEverything() {
        PolicyEntity p = policy("allow-all", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")), List.of());
        when(policyRepository.findAll()).thenReturn(List.of(p));

        assertThat(engine.evaluate(context("x", List.of(), "/anything", "POST")).effect())
            .isEqualTo(Effect.PERMIT);
    }

    // -----------------------------------------------------------------------
    // Condições — todos os Operators
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Operator CONTAINS: role presente na lista → PERMIT")
    void evaluate_ConditionContains_RolePresent_Permit() {
        PolicyEntity p = policy("admin-only", Effect.PERMIT, 1,
            target(List.of("/api/admin"), List.of("GET")),
            List.of(cond("subject.roles", Operator.CONTAINS, "ADMIN")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            context("admin_user", List.of("ADMIN", "USER"), "/api/admin", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Operator CONTAINS: role ausente na lista → DENY")
    void evaluate_ConditionContains_RoleAbsent_Deny() {
        PolicyEntity p = policy("admin-only", Effect.PERMIT, 1,
            target(List.of("/api/admin"), List.of("GET")),
            List.of(cond("subject.roles", Operator.CONTAINS, "ADMIN")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            context("regular_user", List.of("USER"), "/api/admin", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
    }

    @Test
    @DisplayName("Operator EQUALS: atributo igual → PERMIT")
    void evaluate_ConditionEquals_Matches_Permit() {
        PolicyEntity p = policy("env-policy", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("environment.ip", Operator.EQUALS, "127.0.0.1")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        Subject s  = new Subject("alice", List.of(), Map.of(), true);
        Resource r = new Resource("/api/data", "API", "PUBLIC");
        Environment env = new Environment("127.0.0.1", Instant.now(), 0);

        assertThat(engine.evaluate(new AccessContext(s, r, "GET", env)).effect())
            .isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Operator EQUALS: atributo diferente → DENY")
    void evaluate_ConditionEquals_Mismatches_Deny() {
        PolicyEntity p = policy("ip-restrict", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("environment.ip", Operator.EQUALS, "127.0.0.1")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        Subject s  = new Subject("alice", List.of(), Map.of(), true);
        Resource r = new Resource("/api/data", "API", "PUBLIC");
        Environment env = new Environment("10.0.0.99", Instant.now(), 0);

        assertThat(engine.evaluate(new AccessContext(s, r, "GET", env)).effect())
            .isEqualTo(Effect.DENY);
    }

    @Test
    @DisplayName("Operator NOT_EQUALS: atributo diferente do valor proibido → PERMIT")
    void evaluate_ConditionNotEquals_Different_Permit() {
        PolicyEntity p = policy("block-external", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("environment.ip", Operator.NOT_EQUALS, "0.0.0.0")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        Subject s  = new Subject("alice", List.of(), Map.of(), true);
        Resource r = new Resource("/api/data", "API", "PUBLIC");
        Environment env = new Environment("192.168.1.5", Instant.now(), 0);

        assertThat(engine.evaluate(new AccessContext(s, r, "GET", env)).effect())
            .isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Operator GREATER_THAN: valor numérico maior → PERMIT")
    void evaluate_ConditionGreaterThan_ValueIsGreater_Permit() {
        PolicyEntity p = policy("min-score", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("subject.attributes.score", Operator.GREATER_THAN, "50")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            contextWithAttributes("alice", List.of(), Map.of("score", "75"), "/api/data", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Operator GREATER_THAN: valor igual → DENY (não é estritamente maior)")
    void evaluate_ConditionGreaterThan_ValueEqual_Deny() {
        PolicyEntity p = policy("min-score", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("subject.attributes.score", Operator.GREATER_THAN, "50")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            contextWithAttributes("alice", List.of(), Map.of("score", "50"), "/api/data", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
    }

    @Test
    @DisplayName("Operator LESS_THAN: valor menor → PERMIT")
    void evaluate_ConditionLessThan_ValueIsLess_Permit() {
        PolicyEntity p = policy("max-risk", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("subject.attributes.risk", Operator.LESS_THAN, "30")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            contextWithAttributes("alice", List.of(), Map.of("risk", "10"), "/api/data", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.PERMIT);
    }

    // -----------------------------------------------------------------------
    // Prioridade entre políticas conflitantes
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Política de maior prioridade prevalece sobre a de menor prioridade")
    void evaluate_ConflictingPolicies_HigherPriorityWins() {
        PolicyEntity lowPriDeny = policy("deny-all", Effect.DENY, 1,
            target(List.of("/api/resource"), List.of("GET")), List.of());
        PolicyEntity highPriPermit = policy("admin-permit", Effect.PERMIT, 100,
            target(List.of("/api/resource"), List.of("GET")), List.of());

        when(policyRepository.findAll()).thenReturn(List.of(lowPriDeny, highPriPermit));

        PolicyEvaluationResult result = engine.evaluate(
            context("alice", List.of("ADMIN"), "/api/resource", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.PERMIT);
        assertThat(result.reason()).contains("admin-permit");
    }

    @Test
    @DisplayName("Política DENY de maior prioridade derruba o PERMIT de menor prioridade")
    void evaluate_HighPriorityDeny_OverridesLowPriorityPermit() {
        PolicyEntity lowPriPermit = policy("default-permit", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")), List.of());
        PolicyEntity highPriDeny = policy("explicit-deny", Effect.DENY, 50,
            target(List.of("/api/sensitive"), List.of("*")), List.of());

        when(policyRepository.findAll()).thenReturn(List.of(lowPriPermit, highPriDeny));

        PolicyEvaluationResult result = engine.evaluate(
            context("alice", List.of("USER"), "/api/sensitive", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
        assertThat(result.reason()).contains("explicit-deny");
    }

    // -----------------------------------------------------------------------
    // Condição com atributo null
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Atributo de contexto null → condição falha → DENY")
    void evaluate_NullContextAttribute_ConditionFails_Deny() {
        PolicyEntity p = policy("attr-check", Effect.PERMIT, 1,
            target(List.of("*"), List.of("*")),
            List.of(cond("subject.attributes.nonexistent", Operator.EQUALS, "someValue")));
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            contextWithAttributes("alice", List.of(), Map.of(), "/api/data", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
    }

    // -----------------------------------------------------------------------
    // Política sem condições (match apenas por target)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Política sem condições: target match suficiente para PERMIT")
    void evaluate_PolicyWithNoConditions_TargetMatchSuffices() {
        PolicyEntity p = policy("open-policy", Effect.PERMIT, 1,
            target(List.of("/api/public"), List.of("GET")), List.of());
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            context("anyone", List.of(), "/api/public", "GET"));

        assertThat(result.effect()).isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("Política DENY sem condições: nega imediatamente")
    void evaluate_DenyPolicyWithNoConditions_DeniesImmediately() {
        PolicyEntity p = policy("block-delete", Effect.DENY, 1,
            target(List.of("/api/data"), List.of("DELETE")), List.of());
        when(policyRepository.findAll()).thenReturn(List.of(p));

        PolicyEvaluationResult result = engine.evaluate(
            context("admin", List.of("ADMIN"), "/api/data", "DELETE"));

        assertThat(result.effect()).isEqualTo(Effect.DENY);
    }
}
