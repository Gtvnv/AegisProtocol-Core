package br.com.github.gtvnv.retention.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.retention.config.RetentionProperties;
import br.com.github.gtvnv.retention.domain.RetentionCheckpoint;
import br.com.github.gtvnv.retention.repository.RetentionCheckpointRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Satélite Retention Engine — arquiva em lotes com checkpoint, nunca apaga
 * do Ômega (ver RetentionProperties para o porquê).
 */
@ExtendWith(MockitoExtension.class)
class RetentionEngineServiceTest {

    @Mock private AuditChainRepository chainRepository;
    @Mock private RetentionCheckpointRepository checkpointRepository;
    @Mock private RetentionArchiveWriter archiveWriter;
    @Mock private AuditEventPublisher chainPublisher;

    private RetentionProperties properties;
    private RetentionEngineService service;

    @BeforeEach
    void setUp() {
        properties = new RetentionProperties();
        properties.setBatchSize(2);
        properties.setChainRetentionDays(365);
        service = new RetentionEngineService(chainRepository, checkpointRepository, archiveWriter, properties, chainPublisher);

        lenient().when(checkpointRepository.save(any())).thenAnswer(inv -> {
            RetentionCheckpoint c = inv.getArgument(0);
            if (c.getId() == null) {
                c.setId(UUID.randomUUID());
            }
            return c;
        });
    }

    private AuditChainEntry entry(String actor, long seq, String selfHash) {
        return AuditChainEntry.builder()
                .id(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .eventType(AuditEventType.LOGIN_SUCCESS)
                .actor(actor)
                .sequenceNumber(seq)
                .previousHash("prev-" + seq)
                .selfHash(selfHash)
                .build();
    }

    // -----------------------------------------------------------------------
    // runSweep — sem entries fora da janela
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sem entries fora da janela de retenção, nenhum checkpoint é criado")
    void runSweep_NoEntriesOutsideWindow_CreatesNothing() throws IOException {
        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("alice"));
        when(checkpointRepository.findFirstByActorOrderByToSequenceDesc("alice")).thenReturn(Optional.empty());
        when(chainRepository.findByActorAndTimestampBeforeAndSequenceNumberGreaterThanOrderBySequenceNumberAsc(
                eq("alice"), any(), eq(0L), any())).thenReturn(List.of());

        RetentionEngineService.SweepResult result = service.runSweep();

        assertThat(result.actorsArchived()).isZero();
        assertThat(result.checkpointsCreated()).isZero();
        assertThat(result.entriesArchived()).isZero();
        verify(archiveWriter, never()).write(any(), any());
        verifyNoInteractions(chainPublisher);
    }

    // -----------------------------------------------------------------------
    // runSweep — um lote parcial (menor que batchSize) = ator está em dia
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Lote menor que batchSize gera um checkpoint e para — não repagina à toa")
    void runSweep_PartialBatch_CreatesOneCheckpointAndStops() throws IOException {
        // batchSize=2 no setUp: 1 entry é estritamente MENOR — só assim o
        // corte "batch.size() < batchSize" para sozinho, sem depender do
        // mock de checkpoint avançar (que, sendo estático, nunca avançaria
        // — diferente do banco real — e giraria pra sempre se o lote viesse cheio).
        List<AuditChainEntry> batch = List.of(entry("alice", 1, "h1"));

        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("alice"));
        when(checkpointRepository.findFirstByActorOrderByToSequenceDesc("alice")).thenReturn(Optional.empty());
        when(chainRepository.findByActorAndTimestampBeforeAndSequenceNumberGreaterThanOrderBySequenceNumberAsc(
                eq("alice"), any(), eq(0L), any())).thenReturn(batch);
        when(archiveWriter.write(eq("alice"), eq(batch)))
                .thenReturn(new RetentionArchiveWriter.WrittenArchive(Path.of("audit-archive/alice/1-1.ndjson"), "checksum-abc"));

        RetentionEngineService.SweepResult result = service.runSweep();

        assertThat(result.actorsArchived()).isEqualTo(1);
        assertThat(result.checkpointsCreated()).isEqualTo(1);
        assertThat(result.entriesArchived()).isEqualTo(1);

        ArgumentCaptor<RetentionCheckpoint> captor = ArgumentCaptor.forClass(RetentionCheckpoint.class);
        verify(checkpointRepository).save(captor.capture());
        RetentionCheckpoint saved = captor.getValue();
        assertThat(saved.getActor()).isEqualTo("alice");
        assertThat(saved.getFromSequence()).isEqualTo(1L);
        assertThat(saved.getToSequence()).isEqualTo(1L);
        assertThat(saved.getEntryCount()).isEqualTo(1);
        assertThat(saved.getArchiveChecksum()).isEqualTo("checksum-abc");
        assertThat(saved.getLastEntrySelfHash()).isEqualTo("h1");
        assertThat(saved.getCheckpointHash()).hasSize(64); // SHA-256 hex

        verify(chainPublisher).publishRetentionEvent(
                eq(AuditEventType.RETENTION_CHECKPOINT_CREATED), eq("alice"), any(), eq(1));

        // não deve ter tentado paginar de novo
        verify(chainRepository, times(1)).findByActorAndTimestampBeforeAndSequenceNumberGreaterThanOrderBySequenceNumberAsc(
                eq("alice"), any(), anyLong(), any());
    }

    // -----------------------------------------------------------------------
    // runSweep — backlog maior que batchSize: pagina até esgotar
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Backlog maior que batchSize gera múltiplos checkpoints na mesma sweep, avançando o cursor")
    void runSweep_BacklogLargerThanBatch_PaginatesUntilCaughtUp() throws IOException {
        List<AuditChainEntry> firstBatch = List.of(entry("alice", 1, "h1"), entry("alice", 2, "h2")); // cheio (== batchSize)
        List<AuditChainEntry> secondBatch = List.of(entry("alice", 3, "h3")); // parcial — para aqui

        RetentionCheckpoint firstCheckpoint = RetentionCheckpoint.builder()
                .id(UUID.randomUUID()).actor("alice").toSequence(2L).build();

        when(chainRepository.findAllDistinctActors()).thenReturn(List.of("alice"));
        when(checkpointRepository.findFirstByActorOrderByToSequenceDesc("alice"))
                .thenReturn(Optional.empty(), Optional.of(firstCheckpoint));

        when(chainRepository.findByActorAndTimestampBeforeAndSequenceNumberGreaterThanOrderBySequenceNumberAsc(
                eq("alice"), any(), eq(0L), any())).thenReturn(firstBatch);
        when(chainRepository.findByActorAndTimestampBeforeAndSequenceNumberGreaterThanOrderBySequenceNumberAsc(
                eq("alice"), any(), eq(2L), any())).thenReturn(secondBatch);

        when(archiveWriter.write(eq("alice"), any()))
                .thenReturn(new RetentionArchiveWriter.WrittenArchive(Path.of("f1"), "cksum1"))
                .thenReturn(new RetentionArchiveWriter.WrittenArchive(Path.of("f2"), "cksum2"));

        RetentionEngineService.SweepResult result = service.runSweep();

        assertThat(result.checkpointsCreated()).isEqualTo(2);
        assertThat(result.entriesArchived()).isEqualTo(3);
        verify(checkpointRepository, times(2)).save(any());
        verify(chainPublisher, times(2)).publishRetentionEvent(
                eq(AuditEventType.RETENTION_CHECKPOINT_CREATED), eq("alice"), any(), anyInt());
    }

    // -----------------------------------------------------------------------
    // verify — checksum bate / não bate / arquivo sumiu
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verify() retorna intact=true quando o checksum recalculado bate com o gravado")
    void verify_ChecksumMatches_Intact() throws IOException {
        UUID id = UUID.randomUUID();
        RetentionCheckpoint checkpoint = RetentionCheckpoint.builder()
                .id(id).actor("alice").archiveFile("audit-archive/alice/1-2.ndjson").archiveChecksum("same-hash").build();
        when(checkpointRepository.findById(id)).thenReturn(Optional.of(checkpoint));
        when(archiveWriter.checksumOf(Path.of("audit-archive/alice/1-2.ndjson"))).thenReturn("same-hash");

        RetentionEngineService.VerificationResult result = service.verify(id);

        assertThat(result.intact()).isTrue();
        assertThat(result.expectedChecksum()).isEqualTo(result.actualChecksum());
    }

    @Test
    @DisplayName("verify() retorna intact=false quando o arquivo arquivado foi adulterado")
    void verify_ChecksumMismatch_NotIntact() throws IOException {
        UUID id = UUID.randomUUID();
        RetentionCheckpoint checkpoint = RetentionCheckpoint.builder()
                .id(id).actor("alice").archiveFile("audit-archive/alice/1-2.ndjson").archiveChecksum("original-hash").build();
        when(checkpointRepository.findById(id)).thenReturn(Optional.of(checkpoint));
        when(archiveWriter.checksumOf(Path.of("audit-archive/alice/1-2.ndjson"))).thenReturn("tampered-hash");

        RetentionEngineService.VerificationResult result = service.verify(id);

        assertThat(result.intact()).isFalse();
    }

    @Test
    @DisplayName("verify() não propaga IOException — reporta arquivo ausente/ilegível como não íntegro")
    void verify_ArchiveFileMissing_ReportsNotIntactWithoutThrowing() throws IOException {
        UUID id = UUID.randomUUID();
        RetentionCheckpoint checkpoint = RetentionCheckpoint.builder()
                .id(id).actor("alice").archiveFile("audit-archive/alice/gone.ndjson").archiveChecksum("expected").build();
        when(checkpointRepository.findById(id)).thenReturn(Optional.of(checkpoint));
        when(archiveWriter.checksumOf(any())).thenThrow(new IOException("file not found"));

        RetentionEngineService.VerificationResult result = service.verify(id);

        assertThat(result.intact()).isFalse();
        assertThat(result.actualChecksum()).contains("AUSENTE");
    }

    @Test
    @DisplayName("verify() com id inexistente lança NoSuchElementException")
    void verify_UnknownCheckpoint_Throws() {
        UUID id = UUID.randomUUID();
        when(checkpointRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verify(id))
                .isInstanceOf(java.util.NoSuchElementException.class);
    }

    // -----------------------------------------------------------------------
    // markPurged — registra (nunca executa) o purge físico manual
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("markPurged() grava purgedAt/purgedBy e publica RETENTION_PHYSICAL_PURGE_RECORDED")
    void markPurged_UnpurgedCheckpoint_RecordsPurgeAndPublishesEvent() {
        UUID id = UUID.randomUUID();
        RetentionCheckpoint checkpoint = RetentionCheckpoint.builder()
                .id(id).actor("alice").entryCount(3).build();
        when(checkpointRepository.findById(id)).thenReturn(Optional.of(checkpoint));

        RetentionCheckpoint result = service.markPurged(id, "dba_root");

        assertThat(result.getPurgedAt()).isNotNull();
        assertThat(result.getPurgedBy()).isEqualTo("dba_root");
        verify(chainPublisher).publishRetentionEvent(
                eq(AuditEventType.RETENTION_PHYSICAL_PURGE_RECORDED), eq("dba_root"), eq(id.toString()), eq(3));
    }

    @Test
    @DisplayName("markPurged() em checkpoint já purgado lança IllegalStateException — falha alto, não é idempotente")
    void markPurged_AlreadyPurgedCheckpoint_Throws() {
        UUID id = UUID.randomUUID();
        Instant firstPurge = Instant.now().minusSeconds(3600);
        RetentionCheckpoint checkpoint = RetentionCheckpoint.builder()
                .id(id).actor("alice").entryCount(3).purgedAt(firstPurge).purgedBy("dba_root").build();
        when(checkpointRepository.findById(id)).thenReturn(Optional.of(checkpoint));

        assertThatThrownBy(() -> service.markPurged(id, "outro_dba"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("já foi marcado como purgado");

        verify(checkpointRepository, never()).save(any());
        verifyNoInteractions(chainPublisher);
    }

    @Test
    @DisplayName("markPurged() com id inexistente lança NoSuchElementException")
    void markPurged_UnknownCheckpoint_Throws() {
        UUID id = UUID.randomUUID();
        when(checkpointRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.markPurged(id, "dba_root"))
                .isInstanceOf(java.util.NoSuchElementException.class);
    }
}
