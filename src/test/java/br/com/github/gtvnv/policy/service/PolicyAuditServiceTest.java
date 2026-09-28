package br.com.github.gtvnv.policy.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.domain.entity.PolicyEntity;
import br.com.github.gtvnv.domain.policy.Effect;
import br.com.github.gtvnv.domain.policy.Policy;
import br.com.github.gtvnv.domain.policy.Target;
import br.com.github.gtvnv.domain.repository.PolicyRepository;
import br.com.github.gtvnv.policy.dto.PolicyRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyAuditServiceTest {

    @Mock private PolicyRepository repository;
    @Mock private AuditEventPublisher chainPublisher;

    private PolicyAuditService service;

    @BeforeEach
    void setUp() {
        service = new PolicyAuditService(repository, chainPublisher);
        lenient().when(repository.save(any())).thenAnswer(inv -> {
            PolicyEntity e = inv.getArgument(0);
            if (e.getId() == null) {
                e.setId(UUID.randomUUID());
            }
            return e;
        });
    }

    private PolicyRequest request(String name, int priority) {
        return new PolicyRequest(name, "desc", Effect.PERMIT, priority,
                new Target(List.of("/api/secret"), List.of("GET")), List.of());
    }

    // -----------------------------------------------------------------------
    // create
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("create() salva a política e publica POLICY_CREATED com o snapshot 'after'")
    void create_SavesAndPublishesWithAfterSnapshot() {
        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);

        PolicyEntity result = service.create(request("POL-NEW", 5), "admin1");

        assertThat(result.getName()).isEqualTo("POL-NEW");
        assertThat(result.getId()).isNotNull();

        verify(chainPublisher).publishPolicyEvent(
                eq(AuditEventType.POLICY_CREATED), eq("admin1"), eq(result.getId().toString()),
                contains("POL-NEW"), payloadCaptor.capture());

        Map<String, Object> snapshot = payloadCaptor.getValue();
        assertThat(snapshot).containsKey("after");
        assertThat(snapshot).doesNotContainKey("before");
        assertThat(((Policy) snapshot.get("after")).name()).isEqualTo("POL-NEW");
    }

    // -----------------------------------------------------------------------
    // update
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("update() publica POLICY_UPDATED com snapshots 'before' E 'after' distintos")
    void update_PublishesWithBeforeAndAfterSnapshots() {
        UUID id = UUID.randomUUID();
        PolicyEntity existing = PolicyEntity.builder()
                .id(id).name("POL-OLD").effect(Effect.DENY).priority(1)
                .target(new Target(List.of("/api/x"), List.of("GET"))).conditions(List.of())
                .build();
        when(repository.findById(id)).thenReturn(Optional.of(existing));

        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);

        PolicyEntity result = service.update(id, request("POL-RENAMED", 9), "admin1");

        assertThat(result.getName()).isEqualTo("POL-RENAMED");
        assertThat(result.getPriority()).isEqualTo(9);

        verify(chainPublisher).publishPolicyEvent(
                eq(AuditEventType.POLICY_UPDATED), eq("admin1"), eq(id.toString()),
                contains("POL-RENAMED"), payloadCaptor.capture());

        Map<String, Object> snapshot = payloadCaptor.getValue();
        Policy before = (Policy) snapshot.get("before");
        Policy after = (Policy) snapshot.get("after");
        assertThat(before.name()).isEqualTo("POL-OLD");
        assertThat(before.effect()).isEqualTo(Effect.DENY);
        assertThat(after.name()).isEqualTo("POL-RENAMED");
        assertThat(after.effect()).isEqualTo(Effect.PERMIT);
    }

    @Test
    @DisplayName("update() de id desconhecido lança NoSuchElementException sem publicar nada")
    void update_UnknownId_ThrowsWithoutPublishing() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.update(id, request("X", 1), "admin1"))
                .isInstanceOf(java.util.NoSuchElementException.class);
        verifyNoInteractions(chainPublisher);
    }

    // -----------------------------------------------------------------------
    // delete
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("delete() remove a política e publica POLICY_DELETED com o snapshot 'before'")
    void delete_RemovesAndPublishesWithBeforeSnapshot() {
        UUID id = UUID.randomUUID();
        PolicyEntity existing = PolicyEntity.builder()
                .id(id).name("POL-GONE").effect(Effect.PERMIT).priority(3)
                .target(new Target(List.of("/api/x"), List.of("GET"))).conditions(List.of())
                .build();
        when(repository.findById(id)).thenReturn(Optional.of(existing));

        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);

        service.delete(id, "admin1");

        verify(repository).delete(existing);
        verify(chainPublisher).publishPolicyEvent(
                eq(AuditEventType.POLICY_DELETED), eq("admin1"), eq(id.toString()),
                contains("POL-GONE"), payloadCaptor.capture());

        Map<String, Object> snapshot = payloadCaptor.getValue();
        assertThat(snapshot).containsKey("before");
        assertThat(snapshot).doesNotContainKey("after");
        assertThat(((Policy) snapshot.get("before")).name()).isEqualTo("POL-GONE");
    }

    @Test
    @DisplayName("delete() de id desconhecido lança NoSuchElementException sem tocar no repositório de escrita")
    void delete_UnknownId_ThrowsWithoutDeleting() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.delete(id, "admin1"))
                .isInstanceOf(java.util.NoSuchElementException.class);
        verify(repository, never()).delete(any());
        verifyNoInteractions(chainPublisher);
    }

    // -----------------------------------------------------------------------
    // leitura
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getOrThrow() de id desconhecido lança NoSuchElementException")
    void getOrThrow_UnknownId_Throws() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getOrThrow(id)).isInstanceOf(java.util.NoSuchElementException.class);
    }

    @Test
    @DisplayName("listAll() delega direto ao repositório")
    void listAll_DelegatesToRepository() {
        when(repository.findAll()).thenReturn(List.of(PolicyEntity.builder().id(UUID.randomUUID()).name("P1").build()));

        assertThat(service.listAll()).hasSize(1);
    }
}
