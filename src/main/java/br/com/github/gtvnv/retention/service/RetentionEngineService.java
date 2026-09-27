package br.com.github.gtvnv.retention.service;

import br.com.github.gtvnv.audit.chain.domain.AuditChainEntry;
import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.repository.AuditChainRepository;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.retention.config.RetentionProperties;
import br.com.github.gtvnv.retention.domain.RetentionCheckpoint;
import br.com.github.gtvnv.retention.repository.RetentionCheckpointRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * Satélite Retention Engine — arquiva (nunca apaga) entries do Ômega fora da
 * janela de retenção configurada, em lotes com checkpoint assinado. Ver
 * RetentionProperties para o porquê de não fazer DELETE.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RetentionEngineService {

    private final AuditChainRepository chainRepository;
    private final RetentionCheckpointRepository checkpointRepository;
    private final RetentionArchiveWriter archiveWriter;
    private final RetentionProperties properties;
    private final AuditEventPublisher chainPublisher;

    public record SweepResult(int actorsArchived, int checkpointsCreated, int entriesArchived) {}
    public record VerificationResult(UUID checkpointId, boolean intact, String expectedChecksum, String actualChecksum) {}

    @Scheduled(cron = "${aegis.retention.cron:0 0 2 * * *}")
    public void scheduledSweep() {
        if (!properties.isEnabled()) {
            return;
        }
        SweepResult result = runSweep();
        if (result.entriesArchived() > 0) {
            log.info("Retention Engine: sweep agendado — {} ator(es), {} checkpoint(s), {} entries arquivadas.",
                    result.actorsArchived(), result.checkpointsCreated(), result.entriesArchived());
        }
    }

    public SweepResult runSweep() {
        Instant cutoff = Instant.now().minus(properties.getChainRetentionDays(), ChronoUnit.DAYS);
        List<String> actors = chainRepository.findAllDistinctActors();

        int actorsArchived = 0;
        int totalCheckpoints = 0;
        int totalEntries = 0;

        for (String actor : actors) {
            int[] stats = archiveActor(actor, cutoff); // [checkpoints, entries]
            if (stats[1] > 0) {
                actorsArchived++;
            }
            totalCheckpoints += stats[0];
            totalEntries += stats[1];
        }

        return new SweepResult(actorsArchived, totalCheckpoints, totalEntries);
    }

    /** @return {checkpointsCreated, entriesArchived} para este ator. */
    private int[] archiveActor(String actor, Instant cutoff) {
        int checkpoints = 0;
        int entries = 0;

        while (true) {
            long afterSequence = checkpointRepository.findFirstByActorOrderByToSequenceDesc(actor)
                    .map(RetentionCheckpoint::getToSequence)
                    .orElse(0L);

            List<AuditChainEntry> batch = chainRepository
                    .findByActorAndTimestampBeforeAndSequenceNumberGreaterThanOrderBySequenceNumberAsc(
                            actor, cutoff, afterSequence, PageRequest.of(0, properties.getBatchSize()));

            if (batch.isEmpty()) {
                break;
            }

            createCheckpoint(actor, batch);
            checkpoints++;
            entries += batch.size();

            if (batch.size() < properties.getBatchSize()) {
                break; // lote parcial = não tem mais nada pendente pra este ator
            }
        }

        return new int[]{checkpoints, entries};
    }

    @Transactional
    public RetentionCheckpoint createCheckpoint(String actor, List<AuditChainEntry> batch) {
        try {
            RetentionArchiveWriter.WrittenArchive archive = archiveWriter.write(actor, batch);
            AuditChainEntry last = batch.get(batch.size() - 1);
            long fromSeq = batch.get(0).getSequenceNumber();
            long toSeq = last.getSequenceNumber();

            String checkpointHash = computeCheckpointHash(actor, fromSeq, toSeq, archive.checksum(), last.getSelfHash());

            RetentionCheckpoint checkpoint = checkpointRepository.save(RetentionCheckpoint.builder()
                    .actor(actor)
                    .fromSequence(fromSeq)
                    .toSequence(toSeq)
                    .entryCount(batch.size())
                    .archiveFile(archive.file().toString())
                    .archiveChecksum(archive.checksum())
                    .lastEntrySelfHash(last.getSelfHash())
                    .checkpointHash(checkpointHash)
                    .createdAt(Instant.now())
                    .build());

            chainPublisher.publishRetentionEvent(AuditEventType.RETENTION_CHECKPOINT_CREATED,
                    actor, checkpoint.getId().toString(), batch.size());

            return checkpoint;
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao arquivar lote de retenção para actor=" + actor, e);
        }
    }

    /** Recalcula o checksum do arquivo arquivado e compara com o gravado no checkpoint — detecta adulteração pós-arquivamento. */
    public VerificationResult verify(UUID checkpointId) {
        RetentionCheckpoint checkpoint = checkpointRepository.findById(checkpointId)
                .orElseThrow(() -> new NoSuchElementException("Checkpoint não encontrado: " + checkpointId));

        try {
            String actualChecksum = archiveWriter.checksumOf(Path.of(checkpoint.getArchiveFile()));
            boolean intact = actualChecksum.equals(checkpoint.getArchiveChecksum());
            return new VerificationResult(checkpoint.getId(), intact, checkpoint.getArchiveChecksum(), actualChecksum);
        } catch (IOException e) {
            return new VerificationResult(checkpoint.getId(), false, checkpoint.getArchiveChecksum(), "ARQUIVO_AUSENTE_OU_ILEGIVEL");
        }
    }

    private String computeCheckpointHash(String actor, long fromSeq, long toSeq, String archiveChecksum, String lastEntrySelfHash) {
        String input = actor + "|" + fromSeq + "|" + toSeq + "|" + archiveChecksum + "|" + lastEntrySelfHash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }
}
