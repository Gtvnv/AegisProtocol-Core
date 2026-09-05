package br.com.github.gtvnv.audit.chain.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.dto.ChainVerificationReport;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes adversariais do ChainIntegrityVerifier.
 * Cenários: cadeia vazia, íntegra, selfHash adulterado, previousHash quebrado,
 * primeiro entry sem GENESIS, múltiplos atores, detecção do primeiro entry corrompido.
 */
@ExtendWith(MockitoExtension.class)
class ChainIntegrityVerifierTest {

    @Mock private AuditChainRepository repository;
    @Mock private AuditHashEngine       hashEngine;

    @InjectMocks
    private ChainIntegrityVerifier verifier;

    private AuditChainEntry entry(String id, long seq, String prevHash, String selfHash) {
        return AuditChainEntry.builder()
            .id(id)
            .sequenceNumber(seq)
            .actor("alice")
            .eventType(AuditEventType.LOGIN_SUCCESS)
            .timestamp(Instant.ofEpochMilli(seq * 1000L))
            .payloadJson("{}")
            .previousHash(prevHash)
            .selfHash(selfHash)
            .build();
    }

    // -----------------------------------------------------------------------
    // Cadeia vazia
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Cadeia vazia retorna isValid=true com totalEntries=0")
    void verify_EmptyChain_ReturnsValidWithZeroEntries() {
        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of());

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isTrue();
        assertThat(report.totalEntries()).isZero();
        assertThat(report.firstBrokenAt()).isNull();
        assertThat(report.actor()).isEqualTo("alice");
        verifyNoInteractions(hashEngine);
    }

    // -----------------------------------------------------------------------
    // Cadeia íntegra
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Cadeia de 1 entry íntegra retorna isValid=true")
    void verify_SingleIntactEntry_ReturnsValid() {
        AuditChainEntry e = entry("id1", 1L, "GENESIS", "h1");
        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e));
        when(hashEngine.compute("id1", e.getTimestamp(), "alice",
            AuditEventType.LOGIN_SUCCESS, "{}", "GENESIS"))
            .thenReturn("h1");

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isTrue();
        assertThat(report.totalEntries()).isEqualTo(1);
    }

    @Test
    @DisplayName("Cadeia de 3 entries todos íntegros retorna isValid=true")
    void verify_ThreeIntactEntries_ReturnsValid() {
        AuditChainEntry e1 = entry("id1", 1L, "GENESIS", "h1");
        AuditChainEntry e2 = entry("id2", 2L, "h1",      "h2");
        AuditChainEntry e3 = entry("id3", 3L, "h2",      "h3");

        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e1, e2, e3));
        when(hashEngine.compute(eq("id1"), any(), any(), any(), any(), eq("GENESIS"))).thenReturn("h1");
        when(hashEngine.compute(eq("id2"), any(), any(), any(), any(), eq("h1"))).thenReturn("h2");
        when(hashEngine.compute(eq("id3"), any(), any(), any(), any(), eq("h2"))).thenReturn("h3");

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isTrue();
        assertThat(report.totalEntries()).isEqualTo(3);
    }

    // -----------------------------------------------------------------------
    // Adulteração de selfHash
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("selfHash adulterado no entry 2 → detectado, retorna id do entry corrompido")
    void verify_TamperedSelfHashOnSecondEntry_DetectedWithCorrectId() {
        AuditChainEntry e1 = entry("id1", 1L, "GENESIS",       "h1");
        AuditChainEntry e2 = entry("id2", 2L, "h1",            "TAMPERED_HASH");

        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e1, e2));
        when(hashEngine.compute(eq("id1"), any(), any(), any(), any(), eq("GENESIS"))).thenReturn("h1");
        when(hashEngine.compute(eq("id2"), any(), any(), any(), any(), eq("h1"))).thenReturn("h2_real");

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo("id2");
        assertThat(report.totalEntries()).isEqualTo(2);
    }

    @Test
    @DisplayName("selfHash adulterado no primeiro entry → detectado imediatamente")
    void verify_TamperedSelfHashOnFirstEntry_DetectedImmediately() {
        AuditChainEntry e = entry("id1", 1L, "GENESIS", "WRONG_HASH");

        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e));
        when(hashEngine.compute(any(), any(), any(), any(), any(), eq("GENESIS")))
            .thenReturn("correct_hash");

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo("id1");
    }

    @Test
    @DisplayName("selfHash adulterado no entry do meio — entries após ele não são verificados")
    void verify_TamperedMiddleEntry_ReturnsCorrectFirstBroken() {
        AuditChainEntry e1 = entry("id1", 1L, "GENESIS",   "h1");
        AuditChainEntry e2 = entry("id2", 2L, "h1",        "TAMPERED");
        AuditChainEntry e3 = entry("id3", 3L, "TAMPERED",  "h3"); // previousHash = hash adulterado

        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e1, e2, e3));
        when(hashEngine.compute(eq("id1"), any(), any(), any(), any(), eq("GENESIS"))).thenReturn("h1");
        when(hashEngine.compute(eq("id2"), any(), any(), any(), any(), eq("h1"))).thenReturn("h2_real");

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo("id2");
        // id3 não deveria ser verificado — já paramos no id2
        verify(hashEngine, never()).compute(eq("id3"), any(), any(), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // Adulteração de previousHash (elo quebrado)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("previousHash do entry 3 não corresponde ao selfHash do entry 2 → elo quebrado")
    void verify_BrokenPreviousHashLink_DetectedBeforeHashRecomputation() {
        AuditChainEntry e1 = entry("id1", 1L, "GENESIS",   "h1");
        AuditChainEntry e2 = entry("id2", 2L, "h1",        "h2");
        AuditChainEntry e3 = entry("id3", 3L, "WRONG_PREV","h3"); // deveria ser "h2"

        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e1, e2, e3));
        when(hashEngine.compute(eq("id1"), any(), any(), any(), any(), eq("GENESIS"))).thenReturn("h1");
        when(hashEngine.compute(eq("id2"), any(), any(), any(), any(), eq("h1"))).thenReturn("h2");

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo("id3");
        // Quando previousHash falha, não recomputamos selfHash desse entry
        verify(hashEngine, never()).compute(eq("id3"), any(), any(), any(), any(), any());
    }

    // -----------------------------------------------------------------------
    // Primeiro entry com previousHash ≠ GENESIS
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Primeiro entry com previousHash diferente de GENESIS → cadeia corrompida desde a origem")
    void verify_FirstEntryNotGenesis_IsInvalid() {
        AuditChainEntry e1 = entry("id1", 1L, "NOT_GENESIS", "h1");

        when(repository.findByActorOrderBySequenceNumberAsc("alice"))
            .thenReturn(List.of(e1));

        ChainVerificationReport report = verifier.verify("alice");

        assertThat(report.isValid()).isFalse();
        assertThat(report.firstBrokenAt()).isEqualTo("id1");
        verifyNoInteractions(hashEngine);
    }

    // -----------------------------------------------------------------------
    // verifyAll
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verifyAll retorna um relatório por ator distinto")
    void verifyAll_ReturnsOneReportPerActor() {
        when(repository.findAllDistinctActors()).thenReturn(List.of("alice", "bob", "carlos"));
        when(repository.findByActorOrderBySequenceNumberAsc(anyString())).thenReturn(List.of());

        List<ChainVerificationReport> reports = verifier.verifyAll();

        assertThat(reports).hasSize(3);
        assertThat(reports).extracting(ChainVerificationReport::actor)
            .containsExactlyInAnyOrder("alice", "bob", "carlos");
    }

    @Test
    @DisplayName("verifyAll com atores inválidos inclui os relatórios de falha na lista")
    void verifyAll_WithOneCorruptedActor_ReturnsMixedResults() {
        when(repository.findAllDistinctActors()).thenReturn(List.of("good", "bad"));

        // good: cadeia vazia → válida
        when(repository.findByActorOrderBySequenceNumberAsc("good")).thenReturn(List.of());

        // bad: entry com previousHash errado
        AuditChainEntry corrupt = entry("badid1", 1L, "NOT_GENESIS", "h");
        when(repository.findByActorOrderBySequenceNumberAsc("bad")).thenReturn(List.of(corrupt));

        List<ChainVerificationReport> reports = verifier.verifyAll();

        assertThat(reports).hasSize(2);
        assertThat(reports).anySatisfy(r -> {
            assertThat(r.actor()).isEqualTo("good");
            assertThat(r.isValid()).isTrue();
        });
        assertThat(reports).anySatisfy(r -> {
            assertThat(r.actor()).isEqualTo("bad");
            assertThat(r.isValid()).isFalse();
        });
    }
}
