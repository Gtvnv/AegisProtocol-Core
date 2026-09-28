package br.com.github.gtvnv.policy.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.domain.entity.PolicyEntity;
import br.com.github.gtvnv.domain.policy.Policy;
import br.com.github.gtvnv.domain.repository.PolicyRepository;
import br.com.github.gtvnv.policy.dto.PolicyRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * Satélite Policy Audit — até aqui, política ABAC/RBAC só existia via seed
 * inicial (DataSeeder) ou alteração direta no banco; nada auditava QUEM
 * mudou UMA política, nem QUANDO, nem O QUÊ mudou (só as decisões de
 * acesso em runtime iam pro Ômega). Este satélite é a primeira API de
 * verdade pra gerenciar políticas, com cada mutação encadeada no Ômega
 * com snapshot antes/depois.
 *
 * Fecha ISO A.5.16 (gestão de identidade/acesso) e A.8.15 (completude do
 * logging — decisões E as regras que geraram essas decisões).
 */
@Service
@RequiredArgsConstructor
public class PolicyAuditService {

    private final PolicyRepository repository;
    private final AuditEventPublisher chainPublisher;

    public List<PolicyEntity> listAll() {
        return repository.findAll();
    }

    public PolicyEntity getOrThrow(UUID id) {
        return repository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Política não encontrada: " + id));
    }

    @Transactional
    public PolicyEntity create(PolicyRequest request, String actor) {
        PolicyEntity saved = repository.save(PolicyEntity.builder()
                .name(request.name())
                .description(request.description())
                .effect(request.effect())
                .priority(request.priority())
                .target(request.target())
                .conditions(request.conditions())
                .build());

        chainPublisher.publishPolicyEvent(AuditEventType.POLICY_CREATED, actor, saved.getId().toString(),
                "Policy created: " + saved.getName(),
                Map.of("after", saved.toDomain()));
        return saved;
    }

    @Transactional
    public PolicyEntity update(UUID id, PolicyRequest request, String actor) {
        PolicyEntity existing = getOrThrow(id);
        Policy before = existing.toDomain();

        existing.setName(request.name());
        existing.setDescription(request.description());
        existing.setEffect(request.effect());
        existing.setPriority(request.priority());
        existing.setTarget(request.target());
        existing.setConditions(request.conditions());
        PolicyEntity saved = repository.save(existing);

        chainPublisher.publishPolicyEvent(AuditEventType.POLICY_UPDATED, actor, id.toString(),
                "Policy updated: " + saved.getName(),
                Map.of("before", before, "after", saved.toDomain()));
        return saved;
    }

    @Transactional
    public void delete(UUID id, String actor) {
        PolicyEntity existing = getOrThrow(id);
        Policy snapshot = existing.toDomain();
        repository.delete(existing);

        chainPublisher.publishPolicyEvent(AuditEventType.POLICY_DELETED, actor, id.toString(),
                "Policy deleted: " + snapshot.name(),
                Map.of("before", snapshot));
    }
}
