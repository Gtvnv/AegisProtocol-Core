package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes unitários adversariais do AuditChainService.
 * Verifica encadeamento criptográfico, comportamento na ausência de entradas,
 * tolerância a falhas e serialização de payload.
 */
@ExtendWith(MockitoExtension.class)
class AuditChainServiceTest {

    @Mock  private AuditChainRepository repository;
    @Mock  private AuditHashEngine       hashEngine;
    @Spy   private ObjectMapper          objectMapper = new ObjectMapper();

    @InjectMocks
    private AuditChainService service;

    // -----------------------------------------------------------------------
    // Encadeamento: GENESIS e continuidade
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Primeiro entry de um ator deve usar 'GENESIS' como previousHash")
    void append_FirstEntry_UsesGenesisAsPreviousHash() {
        when(repository.findFirstByActorOrderBySequenceNumberDesc("alice"))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), eq("alice"), any(), any(), eq("GENESIS")))
            .thenReturn("hash001");
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AuditChainEntry result = service.append(
            AuditEventType.LOGIN_SUCCESS, "alice",
            "jti1", "127.0.0.1", null, null, "first login", Map.of());

        assertThat(result).isNotNull();
        assertThat(result.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(result.getSequenceNumber()).isEqualTo(1L);
        assertThat(result.getSelfHash()).isEqualTo("hash001");
        assertThat(result.getActor()).isEqualTo("alice");
        assertThat(result.getEventType()).isEqualTo(AuditEventType.LOGIN_SUCCESS);
    }

    @Test
    @DisplayName("Segundo entry usa selfHash do entry anterior como previousHash")
    void append_SubsequentEntry_ChainsPreviousHash() {
        AuditChainEntry existing = AuditChainEntry.builder()
            .id("prev-id")
            .selfHash("prev-hash-abc123")
            .sequenceNumber(5L)
            .actor("alice")
            .timestamp(Instant.now())
            .eventType(AuditEventType.LOGIN_SUCCESS)
            .previousHash("GENESIS")
            .build();

        when(repository.findFirstByActorOrderBySequenceNumberDesc("alice"))
            .thenReturn(Optional.of(existing));
        when(hashEngine.compute(any(), any(), eq("alice"), any(), any(), eq("prev-hash-abc123")))
            .thenReturn("new-hash-xyz");
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AuditChainEntry result = service.append(
            AuditEventType.LOGOUT_SUCCESS, "alice",
            null, null, null, null, null, null);

        assertThat(result.getPreviousHash()).isEqualTo("prev-hash-abc123");
        assertThat(result.getSequenceNumber()).isEqualTo(6L);
        assertThat(result.getSelfHash()).isEqualTo("new-hash-xyz");
    }

    @Test
    @DisplayName("SequenceNumber do primeiro entry é sempre 1, não 0")
    void append_FirstEntry_SequenceNumberIsOne() {
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenReturn("h");
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AuditChainEntry result = service.append(
            AuditEventType.ACCOUNT_CREATED, "bob",
            null, null, null, null, null, null);

        assertThat(result.getSequenceNumber()).isEqualTo(1L);
    }

    // -----------------------------------------------------------------------
    // Independência entre atores
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Atores diferentes possuem cadeias independentes — ambos começam com GENESIS")
    void append_DifferentActors_HaveIndependentChains() {
        when(repository.findFirstByActorOrderBySequenceNumberDesc("alice"))
            .thenReturn(Optional.empty());
        when(repository.findFirstByActorOrderBySequenceNumberDesc("bob"))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), eq("GENESIS")))
            .thenReturn("hash-a", "hash-b");
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AuditChainEntry alice = service.append(
            AuditEventType.LOGIN_SUCCESS, "alice", null, null, null, null, null, null);
        AuditChainEntry bob = service.append(
            AuditEventType.LOGIN_SUCCESS, "bob", null, null, null, null, null, null);

        assertThat(alice.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(bob.getPreviousHash()).isEqualTo("GENESIS");
        assertThat(alice.getSequenceNumber()).isEqualTo(1L);
        assertThat(bob.getSequenceNumber()).isEqualTo(1L);
    }

    // -----------------------------------------------------------------------
    // Tolerância a falhas (não-bloqueante)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Exceção no repository.save retorna null — nunca propaga para o chamador")
    void append_SaveException_ReturnsNullSilently() {
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenReturn("h1");
        when(repository.save(any()))
            .thenThrow(new RuntimeException("Simulated DB failure"));

        AuditChainEntry result = service.append(
            AuditEventType.LOGIN_FAILURE, "attacker",
            null, null, null, null, null, null);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Exceção no hashEngine retorna null — nunca propaga")
    void append_HashEngineException_ReturnsNullSilently() {
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenThrow(new RuntimeException("Hash computation failed"));

        AuditChainEntry result = service.append(
            AuditEventType.IP_BLOCKED_EXPLICIT, "192.168.0.1",
            null, null, null, null, null, null);

        assertThat(result).isNull();
        verify(repository, never()).save(any());
    }

    // -----------------------------------------------------------------------
    // Serialização de payload
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Payload null é serializado como '{}'")
    void append_NullPayload_SerializesAsEmptyJson() {
        ArgumentCaptor<AuditChainEntry> captor = ArgumentCaptor.forClass(AuditChainEntry.class);
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenReturn("h");
        when(repository.save(captor.capture()))
            .thenAnswer(inv -> inv.getArgument(0));

        service.append(AuditEventType.LOGIN_SUCCESS, "alice",
            null, null, null, null, null, null);

        assertThat(captor.getValue().getPayloadJson()).isEqualTo("{}");
    }

    @Test
    @DisplayName("Payload Map.of() vazio é serializado como '{}'")
    void append_EmptyMapPayload_SerializesAsEmptyJson() {
        ArgumentCaptor<AuditChainEntry> captor = ArgumentCaptor.forClass(AuditChainEntry.class);
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenReturn("h");
        when(repository.save(captor.capture()))
            .thenAnswer(inv -> inv.getArgument(0));

        service.append(AuditEventType.LOGIN_SUCCESS, "alice",
            null, null, null, null, null, Map.of());

        assertThat(captor.getValue().getPayloadJson()).isEqualTo("{}");
    }

    @Test
    @DisplayName("Payload com dados é serializado em JSON válido com os campos esperados")
    void append_PopulatedPayload_SerializesCorrectly() {
        ArgumentCaptor<AuditChainEntry> captor = ArgumentCaptor.forClass(AuditChainEntry.class);
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenReturn("h");
        when(repository.save(captor.capture()))
            .thenAnswer(inv -> inv.getArgument(0));

        service.append(AuditEventType.ACCOUNT_CREATED, "alice",
            null, null, null, null, null,
            Map.of("email", "alice@test.com", "role", "USER"));

        String json = captor.getValue().getPayloadJson();
        assertThat(json)
            .contains("email")
            .contains("alice@test.com")
            .contains("role")
            .contains("USER");
    }

    // -----------------------------------------------------------------------
    // Campos opcionais são preservados na entidade salva
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("sessionJti, ipAddress, userAgent e resourcePath são preservados na entry")
    void append_OptionalFields_ArePersistedCorrectly() {
        ArgumentCaptor<AuditChainEntry> captor = ArgumentCaptor.forClass(AuditChainEntry.class);
        when(repository.findFirstByActorOrderBySequenceNumberDesc(any()))
            .thenReturn(Optional.empty());
        when(hashEngine.compute(any(), any(), any(), any(), any(), any()))
            .thenReturn("h");
        when(repository.save(captor.capture()))
            .thenAnswer(inv -> inv.getArgument(0));

        service.append(AuditEventType.SHIELD_REQUEST_BLOCKED, "bob",
            "jti-xyz", "10.0.0.5", "Mozilla/5.0", "/api/admin/sensitive", "blocked", null);

        AuditChainEntry saved = captor.getValue();
        assertThat(saved.getSessionJti()).isEqualTo("jti-xyz");
        assertThat(saved.getIpAddress()).isEqualTo("10.0.0.5");
        assertThat(saved.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(saved.getResourcePath()).isEqualTo("/api/admin/sensitive");
        assertThat(saved.getDetail()).isEqualTo("blocked");
    }
}
