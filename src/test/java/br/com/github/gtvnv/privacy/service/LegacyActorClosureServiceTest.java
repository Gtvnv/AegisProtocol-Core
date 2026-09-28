package br.com.github.gtvnv.privacy.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.AuditChainService;
import br.com.github.gtvnv.privacy.service.LegacyActorClosureService.ClosureResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Satélite PrivacyGate — encerramento de cadeias legadas (pré-existência do
 * PrivacyGate) cujo actor ainda está em claro. Cobre a elegibilidade (mesma
 * regra de ChainAuditListener: exclui ANONYMOUS, já-pseudonimizados e THREAT)
 * e a idempotência (um ator já encerrado não é reprocessado).
 */
@ExtendWith(MockitoExtension.class)
class LegacyActorClosureServiceTest {

    @Mock private AuditChainRepository chainRepository;
    @Mock private AuditChainService chainService;
    @Mock private PrivacyGateService privacyGate;

    private LegacyActorClosureService service;

    @BeforeEach
    void setUp() {
        service = new LegacyActorClosureService(chainRepository, chainService, privacyGate, new ObjectMapper());
    }

    @Test
    @DisplayName("Ator legado em claro (categoria AUTH) é encerrado com LEGACY_ACTOR_CLOSED")
    void runClosure_LegacyIdentityActor_IsClosed() {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("alice"));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(entry("alice", AuditEventType.LOGIN_SUCCESS, "AUTH")));
        when(privacyGate.pseudonymize("alice")).thenReturn("anon_deadbeef");

        ClosureResult result = service.runClosure();

        assertThat(result.actorsClosed()).isEqualTo(1);
        assertThat(result.actorsAlreadyClosed()).isZero();
        assertThat(result.actorsSkippedNotIdentity()).isZero();

        verify(privacyGate).pseudonymize("alice");
        verify(chainService).append(
            eq(AuditEventType.LEGACY_ACTOR_CLOSED), eq("alice"),
            isNull(), isNull(), isNull(), isNull(),
            any(), any());
    }

    @Test
    @DisplayName("Ator já encerrado (última entry é LEGACY_ACTOR_CLOSED) é pulado — idempotente")
    void runClosure_AlreadyClosedActor_IsSkipped() {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("alice"));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("alice")).thenReturn(List.of(
            entry("alice", AuditEventType.LOGIN_SUCCESS, "AUTH"),
            entry("alice", AuditEventType.LEGACY_ACTOR_CLOSED, "PRIVACY")
        ));

        ClosureResult result = service.runClosure();

        assertThat(result.actorsClosed()).isZero();
        assertThat(result.actorsAlreadyClosed()).isEqualTo(1);
        verifyNoInteractions(chainService);
        verify(privacyGate, never()).pseudonymize(any());
    }

    @Test
    @DisplayName("Ator já pseudonimizado (actor começa com anon_) é ignorado")
    void runClosure_AlreadyPseudonymizedActor_IsSkipped() {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("anon_abc123"));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("anon_abc123"))
            .thenReturn(List.of(entry("anon_abc123", AuditEventType.LOGIN_SUCCESS, "AUTH")));

        ClosureResult result = service.runClosure();

        assertThat(result.actorsSkippedNotIdentity()).isEqualTo(1);
        verifyNoInteractions(chainService);
    }

    @Test
    @DisplayName("Ator ANONYMOUS é ignorado")
    void runClosure_AnonymousActor_IsSkipped() {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("ANONYMOUS"));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("ANONYMOUS"))
            .thenReturn(List.of(entry("ANONYMOUS", AuditEventType.LOGIN_FAILURE, "AUTH")));

        ClosureResult result = service.runClosure();

        assertThat(result.actorsSkippedNotIdentity()).isEqualTo(1);
        verifyNoInteractions(chainService);
    }

    @Test
    @DisplayName("Ator de categoria THREAT (actor = IP) é ignorado — não é identidade")
    void runClosure_ThreatCategoryActor_IsSkipped() {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("203.0.113.7"));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("203.0.113.7"))
            .thenReturn(List.of(entry("203.0.113.7", AuditEventType.IP_RATE_LIMIT_EXCEEDED, "THREAT")));

        ClosureResult result = service.runClosure();

        assertThat(result.actorsSkippedNotIdentity()).isEqualTo(1);
        verifyNoInteractions(chainService);
        verify(privacyGate, never()).pseudonymize(any());
    }

    @Test
    @DisplayName("Múltiplos atores: cada um é classificado independentemente")
    void runClosure_MultipleActors_ClassifiedIndependently() {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("alice", "bob", "203.0.113.7"));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(entry("alice", AuditEventType.LOGIN_SUCCESS, "AUTH")));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("bob")).thenReturn(List.of(
            entry("bob", AuditEventType.LOGIN_SUCCESS, "AUTH"),
            entry("bob", AuditEventType.LEGACY_ACTOR_CLOSED, "PRIVACY")
        ));
        when(chainRepository.findByActorOrderBySequenceNumberAsc("203.0.113.7"))
            .thenReturn(List.of(entry("203.0.113.7", AuditEventType.IP_RATE_LIMIT_EXCEEDED, "THREAT")));
        when(privacyGate.pseudonymize("alice")).thenReturn("anon_alice");

        ClosureResult result = service.runClosure();

        assertThat(result.actorsClosed()).isEqualTo(1);
        assertThat(result.actorsAlreadyClosed()).isEqualTo(1);
        assertThat(result.actorsSkippedNotIdentity()).isEqualTo(1);
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    private AuditChainEntry entry(String actor, AuditEventType type, String category) {
        return AuditChainEntry.builder()
            .id(java.util.UUID.randomUUID().toString())
            .timestamp(Instant.now())
            .eventType(type)
            .actor(actor)
            .payloadJson("{\"eventCategory\":\"" + category + "\"}")
            .previousHash("GENESIS")
            .selfHash("fake-hash")
            .sequenceNumber(1L)
            .build();
    }
}
